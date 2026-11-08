// Command server runs the CA chain check web service.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ca-chain-check/assets"
	"ca-chain-check/internal/config"
	"ca-chain-check/internal/netguard"
	"ca-chain-check/internal/probe"
	"ca-chain-check/internal/ratelimit"
	"ca-chain-check/internal/revocation"
	"ca-chain-check/internal/server"
	"ca-chain-check/internal/truststore"
	"ca-chain-check/web"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	cfg, err := config.Load()
	if err != nil {
		slog.Error("invalid configuration", "err", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	loader := &truststore.Loader{URL: cfg.MozillaRootsURL, Fallback: assets.MozillaRootsPEM}
	loader.Init(ctx)
	go loader.Run(ctx, cfg.TruststoreRefresh)

	guard := netguard.New(cfg.TargetDenyCIDRs, cfg.PrivateTargetExtraCIDRs,
		cfg.PrivateTargetClientCIDRs, cfg.IPOverrideClientCIDRs, cfg.AllowRequestIPOverride)
	limiter := ratelimit.New(cfg.RateLimitRPM, cfg.RateLimitBurst)
	go limiter.RunSweeper(ctx.Done())

	srv := &server.Server{
		Cfg: cfg, Guard: guard, Limiter: limiter, Store: loader.Store, Static: web.FS,
		Prober: &probe.Prober{
			Cfg: cfg, Guard: guard, Store: loader.Store,
			Sem:      make(chan struct{}, cfg.MaxConcurrent),
			Resolver: probe.NewResolver(cfg.DNSServers, cfg.DialTimeout),
		},
	}
	if cfg.CheckRevocation {
		srv.Prober.Revocation = &revocation.Checker{
			Guard: guard, Resolver: srv.Prober.Resolver,
			Timeout: cfg.RevocationTimeout, DisableIPv6: cfg.DisableIPv6,
		}
	}
	hs := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		slog.Info("listening", "addr", cfg.ListenAddr, "roots", loader.Store.Info().Count,
			"pendingDistrust", len(cfg.PendingDistrust), "dnsOverrides", len(cfg.DNSOverrides))
		if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server failed", "err", err)
			os.Exit(1)
		}
	}()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = hs.Shutdown(shutdownCtx)
}

// healthcheck probes the local /healthz endpoint (for container healthchecks
// in images without a shell or curl).
func healthcheck() int {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
