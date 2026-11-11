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
	"strings"
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

	loader := &truststore.Loader{
		MozillaURL: cfg.MozillaRootsURL, StoresURL: cfg.CCADBStoresURL, MicrosoftURL: cfg.MicrosoftRootsURL,
		IntermediatesURL: cfg.IntermediatesURL,
		Fallback: truststore.Sources{MozillaPEM: assets.MozillaRootsPEM, StoresCSV: assets.RootStoresCSV,
			MicrosoftCSV: assets.MicrosoftRootsCSV, CrossSignsPEM: assets.CrossSignsPEM},
		FallbackDate: snapshotDate(),
	}
	initErr := loader.Init(ctx)
	go loader.Run(ctx, cfg.TruststoreRefresh, initErr)

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
		WriteTimeout:      cfg.CheckBudget() + 10*time.Second,
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
	stop() // a second SIGTERM or Ctrl-C now exits at once

	// Graceful shutdown, so a rolling update doesn't cut off running checks:
	// 1. fail /readyz and stop reusing idle connections, but keep accepting
	//    requests for ShutdownDelay while load balancers notice;
	// 2. close the listener and wait for running checks, up to one check budget.
	srv.Drain()
	hs.SetKeepAlivesEnabled(false)
	slog.Info("shutting down", "delay", cfg.ShutdownDelay.String(), "maxWait", cfg.CheckBudget().String())
	time.Sleep(cfg.ShutdownDelay)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.CheckBudget()+5*time.Second)
	defer cancel()
	if err := hs.Shutdown(shutdownCtx); err != nil {
		slog.Warn("shutdown timed out with requests still running", "err", err)
		return
	}
	slog.Info("shut down cleanly")
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

// snapshotDate is when the embedded CCADB reports were downloaded.
func snapshotDate() time.Time {
	d, err := time.Parse(time.DateOnly, strings.TrimSpace(assets.RootsDate))
	if err != nil {
		slog.Warn("assets/roots-date.txt is not a YYYY-MM-DD date", "err", err)
	}
	return d
}
