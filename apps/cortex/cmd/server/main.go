// Command server is cortex's entrypoint. For now it ingests SignalDiscovered
// events from stdin (siphon's stdout piped in) and stores them in Postgres.
// The gRPC search API is added in a later step.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/inbound/consumer"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/postgres"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/commands"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/platform/config"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := config.Load()

	pool, err := postgres.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("database connect failed", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := postgres.Migrate(ctx, pool); err != nil {
		logger.Error("migration failed", "error", err)
		os.Exit(1)
	}

	// Compose the hexagon: outbound repo -> ingest use case -> inbound consumer.
	repo := postgres.NewRepo(pool)
	ingest := commands.NewIngestSignal(repo)
	cons := consumer.NewConsumer(ingest)

	logger.Info("cortex ingesting SignalDiscovered events from stdin")
	n, err := cons.Run(ctx, os.Stdin)
	if err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("consumer error", "error", err)
		os.Exit(1)
	}

	total, _ := repo.Count(ctx)
	logger.Info("cortex stopped", "ingested_this_run", n, "total_in_store", total)
}
