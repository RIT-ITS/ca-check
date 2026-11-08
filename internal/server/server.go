// Package server wires HTTP handlers.
package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ca-chain-check/internal/config"
	"ca-chain-check/internal/netguard"
	"ca-chain-check/internal/probe"
	"ca-chain-check/internal/ratelimit"
	"ca-chain-check/internal/theme"
	"ca-chain-check/internal/truststore"
)

// Server bundles handler dependencies.
type Server struct {
	Cfg     *config.Config
	Guard   *netguard.Guard
	Limiter *ratelimit.Limiter
	Prober  *probe.Prober
	Store   *truststore.Store
	Static  fs.FS
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/check", s.check)
	mux.HandleFunc("GET /api/config", s.config)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})
	themeCSS := []byte(theme.CSS(s.Cfg.Theme))
	favicon := theme.Favicon(s.Cfg.Theme)
	ver := assetVersion(s.Static, themeCSS)
	index := versionedPage(s.Static, "index.html", ver)
	help := versionedPage(s.Static, "help.html", ver)
	mux.HandleFunc("GET /theme.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		cacheFor(w, r)
		_, _ = w.Write(themeCSS)
	})
	mux.HandleFunc("GET /favicon.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		cacheFor(w, r)
		_, _ = w.Write(favicon)
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(index)
	})
	mux.HandleFunc("GET /help", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(help)
	})
	files := http.FileServerFS(s.Static)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		cacheFor(w, r)
		files.ServeHTTP(w, r)
	})
	return securityHeaders(mux)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		// Mermaid injects <style> into its SVG, hence 'unsafe-inline' for styles only.
		hd.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("X-Frame-Options", "DENY")
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) config(w http.ResponseWriter, r *http.Request) {
	client := ratelimit.ClientIP(r, s.Cfg.TrustedProxies, s.Cfg.ClientIPHeader)
	writeJSON(w, http.StatusOK, map[string]any{
		"ipOverrideAllowed": s.Guard.OverrideAllowedFor(client),
		"maxIPsPerHost":     s.Cfg.MaxIPsPerHost,
		"trustStore":        s.Store.Info(),
	})
}

func (s *Server) limited(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(ratelimit.RetryAfterSeconds(wait)))
	writeErr(w, http.StatusTooManyRequests, "Rate limit exceeded. Try again in "+strconv.Itoa(ratelimit.RetryAfterSeconds(wait))+"s.")
}

func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	client := ratelimit.ClientIP(r, s.Cfg.TrustedProxies, s.Cfg.ClientIPHeader)
	if !client.IsValid() {
		writeErr(w, http.StatusBadRequest, "cannot determine client address")
		return
	}
	if ok, wait := s.Limiter.AllowN(client, 1); !ok {
		slog.Info("rate limited", "client", client)
		s.limited(w, wait)
		return
	}

	var req probe.Request
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	budget := s.Cfg.DialTimeout*2 + s.Cfg.HandshakeTimeout + 5*time.Second
	ctx, cancel := context.WithTimeout(r.Context(), budget)
	defer cancel()

	host, ips, res, err := s.Prober.Plan(ctx, client, &req)
	if err != nil {
		var ie *probe.InputError
		if errors.As(err, &ie) {
			writeErr(w, http.StatusBadRequest, ie.Msg)
		} else {
			writeErr(w, http.StatusBadGateway, err.Error())
		}
		return
	}
	if extra := probe.Cost(len(ips)) - 1; extra > 0 {
		if ok, wait := s.Limiter.AllowN(client, extra); !ok {
			s.limited(w, wait)
			return
		}
	}
	resp := s.Prober.Run(ctx, client, host, req.Port, req.StartTLS, req.Fallback, ips, res)
	slog.Info("check", "client", client, "host", host, "port", req.Port, "ips", len(ips), "source", res.Source, "starttls", req.StartTLS, "fallback", req.Fallback)
	writeJSON(w, http.StatusOK, resp)
}

// cacheFor lets CDNs and browsers keep versioned asset URLs (?v=...) for a
// year and makes them revalidate everything else, so a redeploy is visible
// at once instead of after the CDN's default TTL.
func cacheFor(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("v") != "" {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
}

// assetVersion hashes every static file plus the theme, so any change to
// the frontend or the local theme yields new asset URLs.
func assetVersion(static fs.FS, extra ...[]byte) string {
	h := sha256.New()
	_ = fs.WalkDir(static, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if b, e := fs.ReadFile(static, p); e == nil {
			h.Write([]byte(p))
			h.Write(b)
		}
		return nil
	})
	for _, b := range extra {
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// versionedPage rewrites the asset references in an HTML page to carry ?v=.
func versionedPage(static fs.FS, name, ver string) []byte {
	b, err := fs.ReadFile(static, name)
	if err != nil {
		return []byte(name + " missing")
	}
	out := string(b)
	for _, a := range []string{"styles.css", "theme.css", "app.js", "help.js", "favicon.svg", "vendor/mermaid.min.js"} {
		out = strings.ReplaceAll(out, `="`+a+`"`, `="`+a+"?v="+ver+`"`)
	}
	return []byte(out)
}
