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
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/nvd"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/application/workflows"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/platform/config"
)

func main() {
	// Logs go to stderr; published events go to stdout (kept separate on purpose).
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := config.Load()

	// Compose the hexagon: outbound adapters -> use case -> inbound adapter.
	source := nvd.New(nil, cfg.NVDBaseURL, cfg.NVDAPIKey)
	pub := publisher.NewStdout(os.Stdout)
	poll := workflows.NewPollSource(source, pub)
	sched := scheduler.New(poll, cfg.PollInterval, cfg.Lookback)

	logger.Info("siphon starting",
		"source", source.Kind().String(),
		"interval", cfg.PollInterval.String(),
		"lookback", cfg.Lookback.String(),
	)

	if err := sched.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("siphon exited with error", "error", err)
		os.Exit(1)
	}
	logger.Info("siphon stopped")
}
