package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"ca-chain-check/internal/config"
	"ca-chain-check/internal/netguard"
	"ca-chain-check/internal/probe"
	"ca-chain-check/internal/ratelimit"
	"ca-chain-check/internal/testpki"
	"ca-chain-check/internal/truststore"
)

// tlsServer starts a TLS listener presenting cert and returns its address.
func tlsServer(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

func setup(t *testing.T, env map[string]string, routes map[string]string) http.Handler {
	t.Helper()
	cfg, err := config.LoadFrom(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	root := testpki.Root("Test Root")
	store := truststore.NewFromCerts(testpki.X509(root), "test")
	guard := netguard.New(cfg.TargetDenyCIDRs, cfg.PrivateTargetExtraCIDRs, cfg.PrivateTargetClientCIDRs, cfg.IPOverrideClientCIDRs, cfg.AllowRequestIPOverride)
	s := &Server{
		Cfg: cfg, Guard: guard, Store: store, Limiter: ratelimit.New(cfg.RateLimitRPM, cfg.RateLimitBurst),
		Static: fstest.MapFS{"index.html": {Data: []byte("hi")}},
		Prober: &probe.Prober{Cfg: cfg, Guard: guard, Store: store, Sem: make(chan struct{}, 4), Resolver: net.DefaultResolver,
			Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _, _ := net.SplitHostPort(addr)
				target, ok := routes[host]
				if !ok {
					t.Errorf("unexpected dial to %s", addr)
					return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError("no route")}
				}
				return (&net.Dialer{}).DialContext(ctx, network, target)
			}},
	}
	return s.Handler()
}

func post(h http.Handler, remote string, body any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", "/api/check", bytes.NewReader(b))
	r.RemoteAddr = remote
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestMultiIPDifferentChainsAndPolicy(t *testing.T) {
	rootA := testpki.Root("Root A")
	interA := testpki.Intermediate("Inter A", rootA)
	leafA := testpki.Leaf("app.cluster.test", interA)
	interB := testpki.Intermediate("Inter B", rootA)
	leafB := testpki.Leaf("app.cluster.test", interB)
	addrA := tlsServer(t, testpki.TLSCert(leafA, interA))
	addrB := tlsServer(t, testpki.TLSCert(leafB, interB))

	h := setup(t, map[string]string{
		"DNS_OVERRIDES": "app.cluster.test=198.51.100.1,198.51.100.2,10.9.9.9,169.254.169.254",
	}, map[string]string{"198.51.100.1": addrA, "198.51.100.2": addrB})

	w := post(h, "203.0.113.50:5555", map[string]any{"host": "app.cluster.test", "port": 443})
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var resp probe.Response
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Resolution.Source != probe.SourceConfigOverride || len(resp.Results) != 4 {
		t.Fatalf("resolution %+v results %d", resp.Resolution, len(resp.Results))
	}
	byIP := map[string]probe.IPResult{}
	for _, r := range resp.Results {
		byIP[r.IP] = r
	}
	if r := byIP["198.51.100.1"]; !r.Tested || r.TLS == nil || r.Analysis == nil || r.TLS.SNI != "app.cluster.test" {
		t.Errorf("A: %+v", r)
	}
	if r := byIP["10.9.9.9"]; r.Tested || r.DenyReason == "" {
		t.Errorf("private should be denied for outside client: %+v", r)
	}
	if r := byIP["169.254.169.254"]; r.Tested || r.DenyReason == "" {
		t.Errorf("metadata should be denied: %+v", r)
	}
	if resp.Consistency.Status != "warn" || len(resp.Consistency.Groups) != 2 {
		t.Errorf("consistency %+v", resp.Consistency)
	}
}

func TestRequestOverrideAndPrivateClient(t *testing.T) {
	root := testpki.Root("R")
	inter := testpki.Intermediate("I", root)
	leaf := testpki.Leaf("svc.internal", inter)
	addr := tlsServer(t, testpki.TLSCert(leaf, inter))
	h := setup(t, map[string]string{
		"PRIVATE_TARGET_CLIENT_CIDRS": "192.168.0.0/16",
		"IP_OVERRIDE_CLIENT_CIDRS":    "192.168.0.0/16",
	}, map[string]string{"10.1.2.3": addr})

	// Outside client may not override.
	if w := post(h, "203.0.113.1:1", map[string]any{"host": "svc.internal", "port": 8443, "connectIPs": []string{"10.1.2.3"}}); w.Code != 400 {
		t.Errorf("outside override: %d %s", w.Code, w.Body)
	}
	// Inside client may override and reach a private target.
	w := post(h, "192.168.5.5:1", map[string]any{"host": "svc.internal", "port": 8443, "connectIPs": []string{"10.1.2.3"}})
	var resp probe.Response
	json.Unmarshal(w.Body.Bytes(), &resp)
	if w.Code != 200 || resp.Resolution.Source != probe.SourceRequestOverride || !resp.Results[0].Tested || resp.Results[0].Error != "" {
		t.Fatalf("inside override: %d %s", w.Code, w.Body)
	}
	if resp.Results[0].Analysis.Chain[0].SubjectCN != "svc.internal" {
		t.Errorf("unexpected chain")
	}
}

func TestRateLimit(t *testing.T) {
	h := setup(t, map[string]string{"RATE_LIMIT_RPM": "1", "RATE_LIMIT_BURST": "2"}, nil)
	body := map[string]any{"host": "", "port": 443} // invalid but still costs a token
	codes := []int{}
	for i := 0; i < 3; i++ {
		codes = append(codes, post(h, "198.51.100.77:1", body).Code)
	}
	if codes[0] != 400 || codes[1] != 400 || codes[2] != 429 {
		t.Fatalf("codes %v", codes)
	}
	w := post(h, "198.51.100.77:1", body)
	if ra, _ := strconv.Atoi(w.Header().Get("Retry-After")); ra < 1 {
		t.Errorf("Retry-After %q", w.Header().Get("Retry-After"))
	}
	if post(h, "198.51.100.78:1", body).Code != 400 {
		t.Error("other client should not be limited")
	}
}

func TestInputValidation(t *testing.T) {
	h := setup(t, map[string]string{"ALLOWED_PORTS": "443", "RATE_LIMIT_BURST": "50", "RATE_LIMIT_RPM": "1000"}, nil)
	for _, body := range []map[string]any{
		{"host": "bad host!", "port": 443},
		{"host": "example.com", "port": 70000},
		{"host": "example.com", "port": 22},
		{"host": "example.com", "port": 443, "extra": 1},
	} {
		if w := post(h, "198.51.100.1:1", body); w.Code != 400 {
			t.Errorf("%v: %d %s", body, w.Code, w.Body)
		}
	}
}

func TestDisableIPv6(t *testing.T) {
	root := testpki.Root("Root V")
	leaf := testpki.Leaf("dual.test", root)
	addr := tlsServer(t, testpki.TLSCert(leaf))
	h := setup(t, map[string]string{
		"DISABLE_IPV6":     "true",
		"RATE_LIMIT_BURST": "50", "RATE_LIMIT_RPM": "1000",
		"DNS_OVERRIDES": "dual.test=198.51.100.7,2001:db8::7;v6only.test=2001:db8::8",
	}, map[string]string{"198.51.100.7": addr})

	w := post(h, "203.0.113.50:5555", map[string]any{"host": "dual.test", "port": 443})
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var resp probe.Response
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Results) != 1 || resp.Results[0].IP != "198.51.100.7" || !resp.Resolution.IPv4Only ||
		len(resp.Resolution.Dropped) != 1 || resp.Resolution.Dropped[0] != "2001:db8::7" {
		t.Fatalf("resolution %+v results %d", resp.Resolution, len(resp.Results))
	}
	for _, body := range []map[string]any{
		{"host": "v6only.test", "port": 443},
		{"host": "2001:db8::9", "port": 443},
		{"host": "dual.test", "port": 443, "connectIPs": []string{"2001:db8::7"}},
	} {
		if w := post(h, "203.0.113.50:5555", body); w.Code != 400 || !strings.Contains(w.Body.String(), "IPv6") {
			t.Errorf("%v: %d %s", body, w.Code, w.Body)
		}
	}
}

func TestVersionedAssets(t *testing.T) {
	cfg, _ := config.LoadFrom(func(string) string { return "" })
	s := &Server{Cfg: cfg, Static: fstest.MapFS{
		"index.html": {Data: []byte(`<link href="styles.css"><script src="app.js"></script>`)},
		"styles.css": {Data: []byte("body{}")},
		"help.html":  {Data: []byte(`<link href="styles.css"><script src="help.js"></script>`)},
	}}
	h := s.Handler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	body := w.Body.String()
	if !strings.Contains(body, `href="styles.css?v=`) || !strings.Contains(body, `src="app.js?v=`) || w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("index: %q %q", body, w.Header().Get("Cache-Control"))
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/help", nil))
	if body := w.Body.String(); w.Code != 200 || !strings.Contains(body, `src="help.js?v=`) || w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("help: %d %q %q", w.Code, body, w.Header().Get("Cache-Control"))
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/styles.css?v=abc", nil))
	if w.Code != 200 || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("asset: %d %q", w.Code, w.Header().Get("Cache-Control"))
	}
}
