// Command server is cortex's entrypoint. It stores vulnerabilities in
// Postgres, indexes them in Elasticsearch, and serves the intelligence gRPC
// API. It can additionally ingest SignalDiscovered events from stdin
// (siphon's stdout piped in) when CORTEX_CONSUME_STDIN=true.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	intelv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/intelligence/v1"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/inbound/consumer"
	grpcadapter "github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/inbound/grpc"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/elasticsearch"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/noopindex"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/postgres"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/commands"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/queries"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
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

	// Compose the hexagon: outbound adapters -> use cases -> inbound adapters.
	repo := postgres.NewRepo(pool)
	index := buildSearchIndex(ctx, logger, cfg)
	ingest := commands.NewIngestSignal(repo, index)
	search := queries.NewSearch(index)

	if cfg.ConsumeStdin {
		runStdinConsumer(ctx, logger, ingest, repo)
		return
	}

	if !cfg.ServeGRPC {
		logger.Error("nothing to do: enable CORTEX_SERVE_GRPC or CORTEX_CONSUME_STDIN")
		os.Exit(1)
	}
	serveGRPC(ctx, logger, cfg, search)
}

// buildSearchIndex returns the Elasticsearch adapter when the cluster answers,
// otherwise a no-op index so ingestion still works without search.
func buildSearchIndex(ctx context.Context, logger *slog.Logger, cfg config.Config) ports.SearchIndex {
	es := elasticsearch.New(nil, cfg.ElasticsearchURL, cfg.IndexName)
	if err := es.Ready(ctx); err != nil {
		logger.Warn("elasticsearch unavailable; search disabled, ingestion continues",
			"url", cfg.ElasticsearchURL, "error", err)
		return noopindex.New()
	}
	logger.Info("elasticsearch ready", "url", cfg.ElasticsearchURL, "index", cfg.IndexName)
	return es
}

// runStdinConsumer ingests protojson events piped in on stdin, then exits.
func runStdinConsumer(ctx context.Context, logger *slog.Logger, ingest *commands.IngestSignal, repo *postgres.Repo) {
	logger.Info("cortex ingesting SignalDiscovered events from stdin")

	n, err := consumer.NewConsumer(ingest).Run(ctx, os.Stdin)
	if err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("consumer error", "error", err)
		os.Exit(1)
	}

	total, _ := repo.Count(ctx)
	logger.Info("cortex stopped", "ingested_this_run", n, "total_in_store", total)
}

// serveGRPC runs the intelligence API until the context is cancelled.
func serveGRPC(ctx context.Context, logger *slog.Logger, cfg config.Config, search *queries.Search) {
	listener, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		logger.Error("grpc listen failed", "addr", cfg.GRPCAddr, "error", err)
		os.Exit(1)
	}

	server := grpc.NewServer()
	intelv1.RegisterIntelligenceServiceServer(server, grpcadapter.NewServer(search))
	reflection.Register(server) // enables grpcurl / grpc_cli exploration

	go func() {
		<-ctx.Done()
		logger.Info("shutting down grpc server")
		server.GracefulStop()
	}()

	logger.Info("cortex grpc server listening", "addr", cfg.GRPCAddr)
	if err := server.Serve(listener); err != nil {
		logger.Error("grpc serve failed", "error", err)
		os.Exit(1)
	}
	logger.Info("cortex stopped")
}
