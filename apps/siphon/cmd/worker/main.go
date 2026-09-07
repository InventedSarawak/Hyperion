// Command worker is siphon's entrypoint: the composition root that wires
// concrete adapters into the application and runs the polling loop.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/inbound/scheduler"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/intelligence"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/publisher"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/repos/githubrepo"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/application/workflows"
	siphonconfig "github.com/inventedsarawak/hyperion/apps/siphon/internal/platform/config"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/platform/sources"
)

func main() {
	checkSources := flag.Bool("check-sources", false,
		"probe every ingestion source once, print a status report, and exit")
	checkLookback := flag.Duration("check-lookback", 24*time.Hour,
		"how far back the -check-sources probe reaches")
	flag.Parse()

	// Logs go to stderr; published events go to stdout (kept separate on purpose).
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := siphonconfig.Load()

	// Resolve which of the documented sources are usable this run.
	registry := sources.Build(cfg, nil)

	// Diagnostic mode: probe each source, report, exit. Publishes nothing.
	if *checkSources {
		runSourceCheck(ctx, registry, *checkLookback)
		return
	}

	reportConfig(logger, cfg)
	reportSources(logger, registry)

	clients := registry.ActiveClients()
	if len(clients) == 0 {
		logger.Error("no active ingestion sources; set credentials in .env (see .env.sample)")
		os.Exit(1)
	}

	// Compose the hexagon: outbound adapters -> use case -> inbound adapter.
	pub := publisher.NewStdout(os.Stdout)
	poll := workflows.NewPollSources(clients, pub)
	sched := scheduler.New(poll, cfg.PollInterval, cfg.Lookback)

	// The supply-chain scan runs alongside on its own, much slower schedule.
	stopScan := startRepositoryScan(ctx, logger, cfg)
	defer stopScan()

	logger.Info("siphon starting",
		"active_sources", registry.ActiveKinds(),
		"interval", cfg.PollInterval.String(),
		"lookback", cfg.Lookback.String(),
	)

	if err := sched.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("siphon exited with error", "error", err)
		os.Exit(1)
	}
	logger.Info("siphon stopped")
}

// startRepositoryScan wires the manifest scanner and runs it in the
// background, returning a function that releases its connection.
//
// It is skipped rather than fatal when unconfigured: reading advisories is
// siphon's primary job, and it must keep working whether or not anyone has
// named repositories to watch or stood cortex up.
func startRepositoryScan(ctx context.Context, logger *slog.Logger, cfg siphonconfig.Config) func() {
	noop := func() {}

	if !cfg.RepoScan.Enabled {
		logger.Info("repository scan disabled (set SIPHON_REPO_SCAN_ENABLED=true)")
		return noop
	}
	if len(cfg.RepoScan.Watchlist) == 0 {
		logger.Warn("repository scan enabled but SIPHON_REPO_WATCHLIST is empty; nothing to scan")
		return noop
	}

	client, err := intelligence.Dial(cfg.RepoScan.CortexAddr)
	if err != nil {
		logger.Error("repository scan disabled: cannot reach intelligence service",
			"addr", cfg.RepoScan.CortexAddr, "error", err)
		return noop
	}

	scan := workflows.NewScanRepositories(
		githubrepo.New(cfg.RepoScan.BaseURL, cfg.RepoScan.Token),
		client,
		cfg.RepoScan.Watchlist,
	)

	logger.Info("repository scan starting",
		"repositories", cfg.RepoScan.Watchlist,
		"interval", cfg.RepoScan.Interval.String(),
		"cortex", cfg.RepoScan.CortexAddr,
		"authenticated", cfg.RepoScan.Token != "",
	)

	go func() {
		// Lookback is irrelevant to a manifest read: its current contents are
		// the whole truth, so the watermark the scheduler tracks is unused.
		if err := scheduler.New(scan, cfg.RepoScan.Interval, 0).Start(ctx); err != nil &&
			!errors.Is(err, context.Canceled) {
			logger.Error("repository scan stopped", "error", err)
		}
	}()

	return func() { _ = client.Close() }
}

// reportSources logs the status of every documented ingestion source, so it is
// obvious which feeds are live and why the others are not.
func reportSources(logger *slog.Logger, registry *sources.Registry) {
	for _, s := range registry.Statuses() {
		if !s.Active {
			logger.Info("source INACTIVE", "source", s.Kind.String(), "name", s.Name, "reason", s.Reason)
			continue
		}
		attrs := []any{"source", s.Kind.String(), "name", s.Name}
		if s.Note != "" {
			attrs = append(attrs, "note", s.Note)
		}
		logger.Info("source ACTIVE", attrs...)
	}
}

// reportConfig logs every resolved setting, with credentials masked.
func reportConfig(logger *slog.Logger, cfg siphonconfig.Config) {
	for _, e := range cfg.Describe() {
		if e.Secret && !e.Set {
			continue // unset optional credentials are covered by the source report
		}
		logger.Debug("config", "key", e.Key, "value", e.Value, "from_env", e.Set)
	}
}

// runSourceCheck probes every source and prints a report on stdout. It exits
// non-zero when an active source fails, so it is usable as a health gate in
// scripts and CI.
func runSourceCheck(ctx context.Context, registry *sources.Registry, lookback time.Duration) {
	results := registry.Check(ctx, lookback)
	fmt.Print(sources.Summary(results))

	for _, r := range results {
		if r.Active && r.Err != nil {
			os.Exit(1)
		}
	}
}
