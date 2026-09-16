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
	"strings"
	"syscall"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/inbound/scheduler"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/intelligence"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/publisher"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/repos/githubrepo"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/nvd"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/osvbulk"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/application/workflows"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/ports"
	siphonconfig "github.com/inventedsarawak/hyperion/apps/siphon/internal/platform/config"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/platform/sources"
)

func main() {
	checkSources := flag.Bool("check-sources", false,
		"probe every ingestion source once, print a status report, and exit")
	checkLookback := flag.Duration("check-lookback", 24*time.Hour,
		"how far back the -check-sources probe reaches")
	scanRepos := flag.Bool("scan-repos", false,
		"scan repositories' manifests once, report, and exit (the whole watchlist unless -repos/-orgs)")
	repos := flag.String("repos", "",
		"comma-separated owner/name list to scan instead of the watchlist")
	orgs := flag.String("orgs", "",
		"comma-separated GitHub orgs/users whose repositories are discovered and scanned")
	backfill := flag.Bool("backfill", false,
		"publish the history of NVD and the OSV ecosystem exports once, then exit")
	backfillFrom := flag.String("backfill-from", time.Now().AddDate(-10, 0, 0).Format(time.DateOnly),
		"earliest publication date the backfill reaches, as YYYY-MM-DD")
	backfillSources := flag.String("backfill-sources", "nvd,osv",
		"comma-separated backfill sources: nvd, osv")
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

	// One-off supply-chain scan: read the watched manifests, report them to
	// cortex, exit. Runs without any ingestion source being active, because
	// reading manifests has nothing to do with polling advisory feeds.
	if *scanRepos {
		runRepositoryScan(ctx, logger, cfg, *repos, *orgs)
		return
	}

	// History, once: what polling can never reach. Events go to stdout like
	// any poll's, so the same pipe into cortex stores them.
	if *backfill {
		runBackfill(ctx, logger, cfg, *backfillFrom, *backfillSources)
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

// startRepositoryScan runs the watchlist scanner in the background,
// returning a function that releases its connection.
//
// It is skipped rather than fatal when it cannot start: reading advisories is
// siphon's primary job, and it must keep working whether or not cortex is up.
func startRepositoryScan(ctx context.Context, logger *slog.Logger, cfg siphonconfig.Config) func() {
	noop := func() {}

	if !cfg.RepoScan.Enabled {
		logger.Info("repository scan disabled (SIPHON_REPO_SCAN_ENABLED=false)")
		return noop
	}

	client, err := intelligence.Dial(cfg.RepoScan.CortexAddr)
	if err != nil {
		logger.Error("repository scan disabled: cannot reach intelligence service",
			"addr", cfg.RepoScan.CortexAddr, "error", err)
		return noop
	}

	repos := githubrepo.New(cfg.RepoScan.BaseURL, cfg.RepoScan.Token)
	scan := workflows.NewScanWatchlist(client, repos, client, cfg.RepoScan.Interval, cfg.RepoScan.RetryInterval)

	logger.Info("watchlist scanner starting",
		"check_every", cfg.RepoScan.WatchInterval.String(),
		"rescan_after", cfg.RepoScan.Interval.String(),
		"retry_after", cfg.RepoScan.RetryInterval.String(),
		"cortex", cfg.RepoScan.CortexAddr,
		"authenticated", cfg.RepoScan.Token != "",
	)

	go func() {
		// Lookback is irrelevant to a manifest read: its current contents are
		// the whole truth, so the watermark the scheduler tracks is unused.
		if err := scheduler.New(scan, cfg.RepoScan.WatchInterval, 0).Start(ctx); err != nil &&
			!errors.Is(err, context.Canceled) {
			logger.Error("watchlist scanner stopped", "error", err)
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

// runRepositoryScan performs one scan and exits non-zero if anything failed,
// so it is usable as a CI or cron step. -repos and -orgs scan exactly what
// they name; with neither, every repository on the watchlist is scanned now,
// whether or not it is due.
func runRepositoryScan(ctx context.Context, logger *slog.Logger, cfg siphonconfig.Config, repoFlag, orgFlag string) {
	client, err := intelligence.Dial(cfg.RepoScan.CortexAddr)
	if err != nil {
		logger.Error("cannot reach the intelligence service",
			"addr", cfg.RepoScan.CortexAddr, "error", err)
		os.Exit(1)
	}
	defer client.Close()

	repos := githubrepo.New(cfg.RepoScan.BaseURL, cfg.RepoScan.Token)

	var scan scheduler.Poller
	switch {
	case repoFlag != "" || orgFlag != "":
		scan = workflows.NewScanRepositories(repos, repos, client, workflows.Targets{
			Repositories:  splitList(repoFlag),
			Organizations: splitList(orgFlag),
			PerOwnerLimit: cfg.RepoScan.PerOwnerLimit,
		})
		logger.Info("scanning named repositories", "repositories", repoFlag, "organizations", orgFlag)
	default:
		// Zero intervals make every tracked repository due.
		scan = workflows.NewScanWatchlist(client, repos, client, 0, 0)
		logger.Info("scanning every repository on the watchlist")
	}

	written, err := scan.Run(ctx, time.Time{})
	if err != nil {
		logger.Error("repository scan finished with errors", "written", written, "error", err)
		os.Exit(1)
	}
	logger.Info("repository scan complete", "dependency_edges_written", written)
}

// runBackfill publishes the history of the chosen sources from a date, and
// exits non-zero if any of them could not be read in full.
func runBackfill(ctx context.Context, logger *slog.Logger, cfg siphonconfig.Config, fromFlag, sourcesFlag string) {
	from, err := time.Parse(time.DateOnly, fromFlag)
	if err != nil {
		logger.Error("invalid -backfill-from; expected YYYY-MM-DD", "value", fromFlag, "error", err)
		os.Exit(1)
	}

	var backfillers []ports.Backfiller
	for _, name := range splitList(sourcesFlag) {
		switch strings.ToLower(name) {
		case "nvd":
			backfillers = append(backfillers, nvd.New(nil, cfg.NVD.BaseURL, cfg.NVD.APIKey,
				nvd.WithPageSize(cfg.NVD.PageSize)))
		case "osv":
			backfillers = append(backfillers, osvbulk.New(nil, cfg.PackageFeeds.BulkBaseURL, cfg.PackageFeeds.BulkEcosystems))
		default:
			logger.Error("unknown backfill source; use nvd and/or osv", "source", name)
			os.Exit(1)
		}
	}
	if len(backfillers) == 0 {
		logger.Error("no backfill sources selected")
		os.Exit(1)
	}
	if cfg.NVD.APIKey == "" && strings.Contains(strings.ToLower(sourcesFlag), "nvd") {
		logger.Warn("no NVD API key: the NVD backfill paces at 6s per page and will take hours")
	}

	logger.Info("backfill starting", "from", from.Format(time.DateOnly), "sources", sourcesFlag)
	published, err := workflows.NewBackfill(backfillers, publisher.NewStdout(os.Stdout)).Run(ctx, from)
	if err != nil {
		logger.Error("backfill finished with errors", "published", published, "error", err)
		os.Exit(1)
	}
	logger.Info("backfill complete", "published", published)
}

// splitList parses a comma-separated flag value, ignoring empty entries.
func splitList(raw string) []string {
	var out []string
	for _, entry := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(entry); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
