// Command worker is siphon's entrypoint: the composition root that wires
// concrete adapters into the application and runs the polling loop.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/inbound/scheduler"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/publisher"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/application/workflows"
	siphonconfig "github.com/inventedsarawak/hyperion/apps/siphon/internal/platform/config"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/platform/sources"
)

func main() {
	// Logs go to stderr; published events go to stdout (kept separate on purpose).
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := siphonconfig.Load()

	// Resolve which of the documented sources are usable this run.
	registry := sources.Build(cfg, nil)
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
