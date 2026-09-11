// Command server is cortex's entrypoint. It stores vulnerabilities in
// Postgres, indexes them in Elasticsearch, and serves the intelligence gRPC
// API. It can additionally ingest SignalDiscovered events from stdin
// (siphon's stdout piped in) when CORTEX_CONSUME_STDIN=true.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	alertingv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/alerting/v1"
	intelv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/intelligence/v1"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/inbound/consumer"
	grpcadapter "github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/inbound/grpc"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/elasticsearch"
	graphadapter "github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/neo4j"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/noopdedupe"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/noopgraph"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/noopindex"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/postgres"
	redisadapter "github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/redis"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/commands"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/queries"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/platform/config"
)

func main() {
	reindex := flag.Bool("reindex", false,
		"rebuild the search index from Postgres, then exit (after a mapping change, or to repair drift)")
	flag.Parse()

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
	graph, closeGraph := buildDependencyGraph(ctx, logger, cfg)
	defer closeGraph()

	// Alerting: the percolator matches, Postgres remembers, Redis suppresses.
	matcher := buildAlertMatcher(ctx, logger, cfg)
	subsRepo := postgres.NewSubscriptionRepo(pool)
	alertRepo := postgres.NewAlertRepo(pool)
	dedupe, closeDedupe := buildDedupeStore(ctx, logger, cfg)
	defer closeDedupe()

	match := commands.NewMatchSignal(matcher, subsRepo, alertRepo, dedupe, cfg.AlertDedupeWindow)
	manageSubs := commands.NewManageSubscriptions(subsRepo, matcher)
	listAlerting := queries.NewListAlerting(subsRepo, alertRepo)

	// The percolator holds no truth of its own, so an index that was lost or
	// rebuilt is repaired from Postgres at boot rather than silently staying
	// empty — an empty index means every subscription stops firing.
	if matcher != nil {
		if n, err := manageSubs.Reindex(ctx); err != nil {
			logger.Warn("could not rebuild the subscription index; some rules may not fire", "error", err)
		} else if n > 0 {
			logger.Info("subscription index rebuilt", "subscriptions", n)
		}
	}

	ingest := commands.NewIngestSignal(repo, index, graph, match)
	ingestDeps := commands.NewIngestDependency(graph)
	search := queries.NewSearch(index)
	blast := queries.NewCalculateBlastRadius(graph, cfg.BlastRadiusMaxDepth)

	if *reindex {
		runReindex(ctx, logger, repo, index)
		return
	}

	if cfg.ConsumeStdin {
		runStdinConsumer(ctx, logger, ingest, repo)
		return
	}

	if !cfg.ServeGRPC {
		logger.Error("nothing to do: enable CORTEX_SERVE_GRPC or CORTEX_CONSUME_STDIN")
		os.Exit(1)
	}
	serveGRPC(ctx, logger, cfg, search, ingestDeps, blast, manageSubs, listAlerting, repo)
}

// buildDependencyGraph returns the Neo4j adapter when the server answers,
// otherwise the no-op graph. Unlike search, the no-op refuses every call: an
// empty blast radius must never be mistaken for "nothing is affected".
func buildDependencyGraph(ctx context.Context, logger *slog.Logger, cfg config.Config) (ports.DependencyGraph, func()) {
	graph, err := graphadapter.Connect(ctx, graphadapter.Config{
		URI:      cfg.Neo4jURI,
		Username: cfg.Neo4jUsername,
		Password: cfg.Neo4jPassword,
		Database: cfg.Neo4jDatabase,
	})
	if err != nil {
		logger.Warn("neo4j unavailable; dependency graph and blast radius disabled",
			"uri", cfg.Neo4jURI, "error", err)
		return noopgraph.New(), func() {}
	}

	if err := graph.EnsureSchema(ctx); err != nil {
		logger.Warn("neo4j schema setup failed; dependency graph disabled",
			"uri", cfg.Neo4jURI, "error", err)
		_ = graph.Close(ctx)
		return noopgraph.New(), func() {}
	}

	logger.Info("neo4j ready", "uri", cfg.Neo4jURI, "database", cfg.Neo4jDatabase)
	return graph, func() { _ = graph.Close(context.WithoutCancel(ctx)) }
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
func serveGRPC(
	ctx context.Context,
	logger *slog.Logger,
	cfg config.Config,
	search *queries.Search,
	ingestDeps *commands.IngestDependency,
	blast *queries.CalculateBlastRadius,
	manageSubs *commands.ManageSubscriptions,
	listAlerting *queries.ListAlerting,
	vulns *postgres.Repo,
) {
	listener, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		logger.Error("grpc listen failed", "addr", cfg.GRPCAddr, "error", err)
		os.Exit(1)
	}

	server := grpc.NewServer()
	intelv1.RegisterIntelligenceServiceServer(server, grpcadapter.NewServer(search, ingestDeps, blast))
	alertingv1.RegisterAlertingServiceServer(server,
		grpcadapter.NewAlertingServer(manageSubs, listAlerting, vulns))
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

// buildAlertMatcher returns the percolator when Elasticsearch answers.
// Alerting simply does not run without it: there is no meaningful degraded
// mode for "match this against every rule".
func buildAlertMatcher(ctx context.Context, logger *slog.Logger, cfg config.Config) ports.AlertMatcher {
	percolator := elasticsearch.NewPercolator(nil, cfg.ElasticsearchURL, cfg.SubscriptionIndex)
	if err := percolator.Ready(ctx); err != nil {
		logger.Warn("elasticsearch unavailable; alerting disabled, ingestion continues",
			"url", cfg.ElasticsearchURL, "error", err)
		return nil
	}
	logger.Info("alerting ready", "index", cfg.SubscriptionIndex)
	return percolator
}

// buildDedupeStore returns Redis when it answers, otherwise a store that
// suppresses nothing. Failing open is deliberate: a duplicate alert is an
// annoyance, a suppressed one is a missed vulnerability.
func buildDedupeStore(ctx context.Context, logger *slog.Logger, cfg config.Config) (ports.DedupeStore, func()) {
	store, err := redisadapter.Connect(ctx, cfg.RedisAddr)
	if err != nil {
		logger.Warn("redis unavailable; alerts will not be de-duplicated",
			"addr", cfg.RedisAddr, "error", err)
		return noopdedupe.New(), func() {}
	}
	logger.Info("redis ready", "addr", cfg.RedisAddr)
	return store, func() { _ = store.Close() }
}

// runReindex rebuilds the search index from Postgres and exits non-zero on
// failure, so it is usable from a script.
func runReindex(ctx context.Context, logger *slog.Logger, repo *postgres.Repo, index ports.SearchIndex) {
	if _, disabled := index.(*noopindex.Index); disabled {
		logger.Error("reindex needs Elasticsearch, and it is unreachable")
		os.Exit(1)
	}
	logger.Info("rebuilding the search index from Postgres")
	report, err := commands.NewReindexSearch(repo, index).Run(ctx)
	if err != nil {
		logger.Error("reindex failed", "written", report.Written, "removed", report.Removed, "error", err)
		os.Exit(1)
	}
	logger.Info("reindex complete", "written", report.Written, "removed", report.Removed)
}
