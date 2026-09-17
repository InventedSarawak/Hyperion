// Command server is cortex's entrypoint. It stores vulnerabilities in
// Postgres, indexes them in Elasticsearch, and serves the intelligence gRPC
// API.
//
// It ingests SignalDiscovered events through one of two inbound adapters:
// the Kafka consumer (CORTEX_KAFKA_ENABLED=true), which runs alongside the
// API, or stdin (CORTEX_CONSUME_STDIN=true) for the pipe that `task ingest`
// and `task backfill` use, which runs instead of it and exits at EOF.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	alertingv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/alerting/v1"
	intelv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/intelligence/v1"
	watchlistv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/watchlist/v1"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/inbound/consumer"
	grpcadapter "github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/inbound/grpc"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/broadcast"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/elasticsearch"
	githubadapter "github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/github"
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
	"github.com/inventedsarawak/hyperion/packages/common/kafka"
)

func main() {
	reindex := flag.Bool("reindex", false,
		"rebuild the search index from Postgres, then exit (after a mapping change, or to repair drift)")
	purgeWithdrawn := flag.Bool("purge-withdrawn", false,
		"remove findings whose source has retracted them (rejected CVE ids stored before the check existed), then exit")
	dryRun := flag.Bool("dry-run", false,
		"with -purge-withdrawn: report what would be removed, and remove nothing")
	pruneGraph := flag.Duration("prune-graph", 0,
		"remove library-to-library edges not confirmed for this long (e.g. 90 days: -prune-graph 2160h), then exit")
	swapIndex := flag.Bool("swap-index", false,
		"rebuild the search index under the current mapping alongside the live one, then move the alias onto it, then exit")
	flag.Parse()

	cfg := config.Load()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel(cfg.LogLevel)}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

	// Malware is triaged by whether anything tracked actually depends on it:
	// 240,000 typosquats nobody has installed would otherwise be 240,000
	// chances to alert on nothing.
	match := commands.NewMatchSignal(matcher, subsRepo, alertRepo, dedupe, cfg.AlertDedupeWindow).
		WithReach(graph)
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

	// The watchlist: which repositories blast radius can reach.
	manageWatchlist := commands.NewManageWatchlist(postgres.NewWatchlist(pool), graph)
	listWatchlist := queries.NewListWatchlist(postgres.NewWatchlist(pool),
		githubadapter.New(nil, cfg.GitHubBaseURL, cfg.GitHubToken))

	// Live feed: ingest announces what it stored, the streaming RPC fans it
	// out to whoever is watching. In memory on purpose — everything announced
	// is already in Postgres, so a watcher that was not connected has lost
	// nothing it cannot ask Search for.
	live := broadcast.New(cfg.StreamBuffer)

	ingest := commands.NewIngestSignal(repo, index, graph, match).
		WithNotifier(live).
		WithReconciler(repo)
	reconcile := commands.NewReconcileIndex(repo, index)
	ingestDeps := commands.NewIngestDependency(graph)
	search := queries.NewSearch(index)
	blast := queries.NewCalculateBlastRadius(graph, cfg.BlastRadiusMaxDepth).WithResolver(repo)
	exposure := queries.NewRepositoryExposure(graph, repo, cfg.BlastRadiusMaxDepth)
	listWatchlist.WithExposure(exposure)

	if *pruneGraph > 0 {
		runPruneGraph(ctx, logger, graph, *pruneGraph, *dryRun)
		return
	}

	if *purgeWithdrawn {
		purge := commands.NewPurgeWithdrawn(repo, ingest)
		if *dryRun {
			purge = purge.DryRun()
		}
		runPurgeWithdrawn(ctx, logger, purge, *dryRun)
		return
	}

	if *swapIndex {
		runSwapIndex(ctx, logger, index)
		return
	}

	if *reindex {
		runReindex(ctx, logger, repo, index)
		return
	}

	if cfg.ConsumeStdin {
		runStdinConsumer(ctx, logger, ingest, repo, cfg.IngestWorkers, cfg.IngestProgressEvery)
		return
	}

	if !cfg.ServeGRPC && !cfg.Kafka.Enabled {
		logger.Error("nothing to do: enable CORTEX_SERVE_GRPC, CORTEX_KAFKA_ENABLED or CORTEX_CONSUME_STDIN")
		os.Exit(1)
	}

	// Ingest and the API share a process. Cancelling this context stops both,
	// so a consumer that gives up takes the server down with it rather than
	// leaving cortex serving data that has quietly stopped being updated.
	runCtx, stopRun := context.WithCancel(ctx)
	defer stopRun()

	consumerFailed := make(chan struct{})
	var failOnce sync.Once
	fail := func(what string, err error) {
		logger.Error(what+" stopped", "error", err)
		failOnce.Do(func() { close(consumerFailed) })
		stopRun()
	}

	if cfg.Kafka.Enabled {
		// Two topics, two groups, two goroutines: advisories and manifest
		// reads are unrelated work, and a backlog of one must not hold up the
		// other.
		go func() {
			if err := runKafkaConsumer(runCtx, logger, ingest, cfg); err != nil {
				fail("kafka ingest", err)
				return
			}
			logger.Info("kafka ingest stopped")
		}()

		go func() {
			if err := runDependencyConsumer(runCtx, logger, ingestDeps, cfg); err != nil {
				fail("dependency ingest", err)
				return
			}
			logger.Info("dependency ingest stopped")
		}()
	}

	// Close whatever gap opened between Postgres and the index — a failed
	// index write, a process stopped between the two — without anyone having
	// to notice and run a reindex by hand.
	go runReconciler(runCtx, logger, reconcile, cfg.ReconcileInterval)

	if cfg.ServeGRPC {
		serveGRPC(runCtx, logger, cfg, search, ingestDeps, blast, manageSubs, listAlerting, repo,
			grpcadapter.NewWatchlistServer(manageWatchlist, listWatchlist), exposure, live)
	} else {
		<-runCtx.Done()
		logger.Info("cortex stopped")
	}

	// A consumer that died is a failed run, whatever the server did.
	select {
	case <-consumerFailed:
		os.Exit(1)
	default:
	}
}

// runDependencyConsumer reads repository manifest observations until the
// context is cancelled.
//
// It has no dead-letter topic of its own: a manifest read that cannot be
// written is almost always the graph being unavailable, which is exactly the
// case that should stop and be retried rather than be set aside. A repeat
// observation of the same repository supersedes the one that failed anyway.
func runDependencyConsumer(ctx context.Context, logger *slog.Logger, ingestDeps *commands.IngestDependency, cfg config.Config) error {
	clientCfg := kafka.Config{Brokers: cfg.Kafka.Brokers, ClientID: "cortex-graph"}
	if err := kafka.EnsureTopic(ctx, clientCfg, cfg.Kafka.DependencyTopic, kafka.DefaultPartitions); err != nil {
		return err
	}

	c, err := kafka.NewConsumer(clientCfg, cfg.Kafka.DependencyTopic, cfg.Kafka.DependencyGroup,
		kafka.WithConsumerLogger(logger))
	if err != nil {
		return err
	}
	defer c.Close()

	handler := consumer.NewDependencyHandler(ingestDeps, logger)

	logger.Info("cortex consuming dependency observations from kafka",
		"brokers", cfg.Kafka.Brokers, "topic", cfg.Kafka.DependencyTopic, "group", cfg.Kafka.DependencyGroup)

	if err := c.Run(ctx, handler); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	logger.Info("dependency ingest finished", "repositories_observed", handler.Observed())
	return nil
}

// runReconciler settles records whose search document is behind, on a timer.
//
// It runs whatever else cortex is doing: the gap it repairs is opened by
// ingest, and closing it is not something to ask an operator to remember.
func runReconciler(ctx context.Context, logger *slog.Logger, reconcile *commands.ReconcileIndex, every time.Duration) {
	if every <= 0 {
		return
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := reconcile.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				logger.Warn("index reconciliation failed", "error", err)
			}
		}
	}
}

// runKafkaConsumer reads the signal topic until the context is cancelled.
//
// The topic is ensured here as well as in siphon so that cortex can be started
// first: consuming a topic that does not exist yet simply waits, and creating
// it means the group registers and its lag is visible from the first moment.
func runKafkaConsumer(ctx context.Context, logger *slog.Logger, ingest *commands.IngestSignal, cfg config.Config) error {
	clientCfg := kafka.Config{Brokers: cfg.Kafka.Brokers, ClientID: "cortex"}
	if err := kafka.EnsureTopic(ctx, clientCfg, cfg.Kafka.Topic, int32(cfg.Kafka.Partitions)); err != nil {
		return err
	}

	opts := []kafka.ConsumerOption{kafka.WithConsumerLogger(logger)}

	// Somewhere to put a record that will never succeed, so it cannot block
	// every record behind it on its partition.
	if cfg.Kafka.DeadLetterEnabled {
		dl, err := kafka.NewDeadLetter(ctx, clientCfg, cfg.Kafka.Topic, cfg.Kafka.DeadLetterTopic, logger)
		if err != nil {
			return err
		}
		defer func() { _ = dl.Close() }()

		opts = append(opts, kafka.WithDeadLetter(dl, cfg.Kafka.MaxConsecutiveDLQ))
		logger.Info("unprocessable records will be set aside",
			"dead_letter_topic", dl.Topic(), "stop_after_consecutive", cfg.Kafka.MaxConsecutiveDLQ)
	}

	opts = append(opts, kafka.WithShutdownGrace(cfg.ShutdownGrace))

	c, err := kafka.NewConsumer(clientCfg, cfg.Kafka.Topic, cfg.Kafka.Group, opts...)
	if err != nil {
		return err
	}
	defer c.Close()

	handler := consumer.NewKafkaHandler(ingest, cfg.IngestProgressEvery, logger)

	// Concurrency comes from the partitions, not from CORTEX_INGEST_WORKERS:
	// the consumer runs one goroutine per partition it is assigned, and a
	// second cortex process takes half of them.
	logger.Info("cortex consuming signals from kafka",
		"brokers", cfg.Kafka.Brokers, "topic", cfg.Kafka.Topic, "group", cfg.Kafka.Group)

	if err := c.Run(ctx, handler); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	logger.Info("kafka ingest finished", "ingested_this_run", handler.Processed())
	return nil
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
func runStdinConsumer(ctx context.Context, logger *slog.Logger, ingest *commands.IngestSignal, repo *postgres.Repo, workers, progressEvery int) {
	logger.Info("cortex ingesting SignalDiscovered events from stdin",
		"workers", workers, "progress_every", progressEvery)

	n, err := consumer.NewConsumer(ingest,
		consumer.WithWorkers(workers),
		consumer.WithProgressEvery(progressEvery),
	).Run(ctx, os.Stdin)
	if err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("consumer error", "error", err)
		os.Exit(1)
	}

	// Counted on a context the interrupt did not cancel: this line is the
	// run's receipt, and a shutdown reporting "total_in_store: 0" would be
	// alarming and wrong.
	total, _ := repo.Count(context.WithoutCancel(ctx))
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
	watchlist *grpcadapter.WatchlistServer,
	exposure *queries.RepositoryExposure,
	live *broadcast.Broadcaster,
) {
	listener, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		logger.Error("grpc listen failed", "addr", cfg.GRPCAddr, "error", err)
		os.Exit(1)
	}

	server := grpc.NewServer()
	intelv1.RegisterIntelligenceServiceServer(server,
		grpcadapter.NewServer(search, ingestDeps, blast, vulns).
			WithRepositoryExposure(exposure).
			WithFindingStream(live))
	watchlistv1.RegisterWatchlistServiceServer(server, watchlist)
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

// runPruneGraph retires library-to-library edges nothing has confirmed for a
// while.
//
// These edges deliberately outlive the repository that taught them — "ajv
// depends on fast-uri" stays true whether or not anyone tracks ajv — but
// nothing re-reads a manifest nobody scans, so they need a way to age out.
func runPruneGraph(ctx context.Context, logger *slog.Logger, graph ports.DependencyGraph, olderThan time.Duration, dryRun bool) {
	pruner, ok := graph.(interface {
		StaleLibraryEdges(context.Context, time.Time) (int, error)
		PruneStaleLibraryEdges(context.Context, time.Time, int) (int, error)
	})
	if !ok {
		logger.Error("pruning needs Neo4j, and it is unreachable")
		os.Exit(1)
	}

	cutoff := time.Now().Add(-olderThan)
	stale, err := pruner.StaleLibraryEdges(ctx, cutoff)
	if err != nil {
		logger.Error("could not count stale library edges", "error", err)
		os.Exit(1)
	}

	if dryRun {
		logger.Info("dry run complete; nothing was removed",
			"would_remove", stale, "not_confirmed_since", cutoff.UTC().Format(time.RFC3339))
		return
	}

	pruned, err := pruner.PruneStaleLibraryEdges(ctx, cutoff, 1000)
	if err != nil {
		logger.Error("prune failed", "pruned", pruned, "error", err)
		os.Exit(1)
	}
	logger.Info("stale library edges retired",
		"pruned", pruned, "not_confirmed_since", cutoff.UTC().Format(time.RFC3339))
}

// runPurgeWithdrawn removes retracted findings and exits non-zero on failure,
// so it is usable from a script.
func runPurgeWithdrawn(ctx context.Context, logger *slog.Logger, purge *commands.PurgeWithdrawn, dryRun bool) {
	what := "removing findings whose source has retracted them"
	if dryRun {
		what = "listing findings whose source has retracted them (removing nothing)"
	}
	logger.Info(what)

	removed, err := purge.Run(ctx)
	if err != nil {
		logger.Error("purge failed", "found", removed, "error", err)
		os.Exit(1)
	}
	if dryRun {
		logger.Info("dry run complete; nothing was removed", "would_remove", removed)
		return
	}
	logger.Info("purge complete", "removed", removed)
}

// runSwapIndex rebuilds the index under the current mapping and moves the alias.
//
// Separate from -reindex because they repair different things. This copies
// documents server-side from the live index, which is fast and is what a
// mapping change needs; -reindex rebuilds from Postgres, which is slower and is
// what you want when the documents themselves are wrong or incomplete.
func runSwapIndex(ctx context.Context, logger *slog.Logger, index ports.SearchIndex) {
	swapper, ok := index.(interface {
		Swap(context.Context) (string, string, error)
	})
	if !ok {
		logger.Error("swapping the index needs Elasticsearch, and it is unreachable")
		os.Exit(1)
	}

	logger.Info("rebuilding the search index alongside the live one")
	from, to, err := swapper.Swap(ctx)
	if err != nil {
		logger.Error("index swap failed; the live index is untouched", "error", err)
		os.Exit(1)
	}
	logger.Info("search index swapped", "from", from, "to", to)
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

// logLevel maps the configured name onto a slog level. An unknown name is
// info: a typo in a log setting must not silence the service.
func logLevel(name string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
