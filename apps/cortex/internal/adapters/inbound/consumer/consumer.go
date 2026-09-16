// Package consumer is an INBOUND adapter: it reads SignalDiscovered events as
// protojson lines (siphon's stdout piped to cortex's stdin) and drives the
// ingest use case. This is cortex's proto boundary — the only inbound place
// that touches the generated contract types.
package consumer

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/common/v1"
	eventsv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/events/v1"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

const maxLineBytes = 4 * 1024 * 1024 // events can be large (many references)

// Ingester is the use case this adapter drives (consumer-side interface).
type Ingester interface {
	Handle(ctx context.Context, v model.Vulnerability) error
}

// Consumer reads protojson events from an io.Reader and ingests each one.
type Consumer struct {
	// progressEvery is how many ingested findings pass between progress
	// lines; 0 silences them.
	progressEvery int
	ingester      Ingester
	workers       int
	log           *slog.Logger
}

// Option customizes a Consumer.
type Option func(*Consumer)

// WithWorkers ingests on n workers at once. Each event is one read, one merge
// and several network writes (Postgres, the search index, the graph, the
// alert percolator), all waiting on I/O, so a single worker leaves every
// backend idle most of the time — a ten-year backfill took hours that way.
func WithWorkers(n int) Option {
	return func(c *Consumer) {
		if n > 0 {
			c.workers = n
		}
	}
}

// NewConsumer wires the adapter to the ingest use case. It ingests on one
// worker, in input order, unless told otherwise.
func NewConsumer(ingester Ingester, opts ...Option) *Consumer {
	c := &Consumer{ingester: ingester, workers: 1, progressEvery: 1000, log: slog.Default()}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Run consumes newline-delimited protojson events until EOF (or ctx is done)
// and returns how many were ingested successfully. Malformed lines and
// per-event ingest failures are logged and skipped, not fatal.
//
// Events are sharded across workers by vulnerability id, not handed to
// whichever worker is free. Ingest is read-merge-write: two workers merging
// observations of the same CVE at once would each read the old record and
// the second write would erase the first's contribution. Pinning an id to one
// worker keeps every CVE's events in order while different CVEs proceed in
// parallel.
func (c *Consumer) Run(ctx context.Context, r io.Reader) (int, error) {
	var (
		processed atomic.Int64
		failed    atomic.Int64
		dropped   atomic.Int64
		wg        sync.WaitGroup
		started   = time.Now()
		lanes     = make([]chan model.Vulnerability, c.workers)
	)
	for i := range lanes {
		lanes[i] = make(chan model.Vulnerability, laneBuffer)
		wg.Add(1)
		go func(lane <-chan model.Vulnerability) {
			defer wg.Done()
			for v := range lane {
				// Shutting down: keep draining, so the reader is never left
				// blocked on a full lane, but do not begin work a dead
				// context will only refuse. These are counted rather than
				// logged one line each — every lane is full when a backfill
				// is interrupted, and hundreds of instant failures bury the
				// reason it stopped.
				if ctx.Err() != nil {
					dropped.Add(1)
					continue
				}
				if err := c.ingester.Handle(ctx, v); err != nil {
					// The same shutdown, caught a moment later: this event
					// was in flight when the context was cancelled. Not a
					// failure of the event, and not worth an error line.
					if errors.Is(err, context.Canceled) {
						dropped.Add(1)
						continue
					}
					failed.Add(1)
					c.log.Error("ingest failed", "cve", v.CVEID, "error", err)
					continue
				}
				done := processed.Add(1)
				c.log.Debug("ingested", "id", v.CVEID, "kind", v.Kind,
					"packages", len(v.AffectedPackages), "sources", v.Sources)
				// A heartbeat rather than a line per finding: a backfill is
				// hundreds of thousands of them, and what a reader needs to
				// know is that it is moving, and how fast.
				if c.progressEvery > 0 && done%int64(c.progressEvery) == 0 {
					c.log.Info("ingest progress",
						"ingested", done,
						"failed", failed.Load(),
						"per_second", int64(float64(done)/time.Since(started).Seconds()),
						"latest", v.CVEID)
				}
			}
		}(lanes[i])
	}

	err := c.read(ctx, r, func(v model.Vulnerability) {
		lanes[laneFor(v.CVEID, len(lanes))] <- v
	})

	for _, lane := range lanes {
		close(lane)
	}
	wg.Wait()
	if n := failed.Load(); n > 0 {
		c.log.Warn("some findings could not be ingested", "failed", n, "ingested", processed.Load())
	}
	// Whatever was still queued when the context was cancelled was never
	// stored. Say how many, so an interrupted run is known to have left a
	// gap rather than assumed to have finished what it read.
	if n := dropped.Load(); n > 0 {
		c.log.Warn("stopped before every finding read was ingested; the rest were dropped",
			"dropped", n, "ingested", processed.Load())
	}
	return int(processed.Load()), err
}

// WithProgressEvery sets how many ingested findings pass between progress
// lines. Zero silences them.
func WithProgressEvery(n int) Option {
	return func(c *Consumer) {
		if n >= 0 {
			c.progressEvery = n
		}
	}
}

// WithLogger sends the consumer's own logging somewhere other than the
// default logger.
func WithLogger(l *slog.Logger) Option {
	return func(c *Consumer) {
		if l != nil {
			c.log = l
		}
	}
}

// laneBuffer lets the reader run a little ahead of each worker.
const laneBuffer = 64

// laneFor picks the worker an id always goes to.
func laneFor(id string, lanes int) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	return int(h.Sum32() % uint32(lanes))
}

// read decodes one event per line and hands each to dispatch.
func (c *Consumer) read(ctx context.Context, r io.Reader, dispatch func(model.Vulnerability)) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}

		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var msg eventsv1.SignalDiscovered
		if err := protojson.Unmarshal(line, &msg); err != nil {
			c.log.Warn("skipping malformed event", "error", err)
			continue
		}
		dispatch(toDomain(&msg))
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("consumer: scan: %w", err)
	}
	return nil
}

// --- mapping: wire contract -> cortex domain ---

// toDomain maps an event onto the domain and normalises its identity before
// it is sharded, so reports of one finding that led with different ids (the
// CVE from NVD, the GHSA from GitHub) land on the same worker.
func toDomain(msg *eventsv1.SignalDiscovered) model.Vulnerability {
	v := msg.GetVulnerability()
	return model.Vulnerability{
		CVEID:            v.GetCveId(),
		Aliases:          v.GetAliases(),
		Kind:             toKind(v.GetKind()),
		Title:            v.GetTitle(),
		Description:      v.GetDescription(),
		Scores:           toScores(v.GetScores()),
		References:       v.GetReferences(),
		Sources:          sourcesFrom(msg.GetSource()),
		PublishedAt:      fromTimestamp(v.GetPublishedAt()),
		ModifiedAt:       fromTimestamp(v.GetModifiedAt()),
		AffectedPackages: toPackageRefs(v.GetAffectedPackages()),
	}.Normalized()
}

// toKind maps the wire kind. Unspecified — every feed that predates the field,
// and every feed that only reports flaws — is an ordinary vulnerability.
func toKind(k commonv1.FindingKind) model.FindingKind {
	if k == commonv1.FindingKind_FINDING_KIND_MALWARE {
		return model.KindMalware
	}
	return model.KindVulnerability
}

func toPackageRefs(refs []*commonv1.PackageRef) []valueobject.PackageRef {
	if len(refs) == 0 {
		return nil
	}
	out := make([]valueobject.PackageRef, 0, len(refs))
	for _, r := range refs {
		out = append(out, valueobject.PackageRef{
			Ecosystem: toEcosystem(r.GetEcosystem()),
			Name:      r.GetName(),
			Version:   r.GetVersion(),
		})
	}
	return out
}

func toEcosystem(e commonv1.Ecosystem) valueobject.Ecosystem {
	switch e {
	case commonv1.Ecosystem_ECOSYSTEM_GO:
		return valueobject.EcosystemGo
	case commonv1.Ecosystem_ECOSYSTEM_NPM:
		return valueobject.EcosystemNPM
	case commonv1.Ecosystem_ECOSYSTEM_PYPI:
		return valueobject.EcosystemPyPI
	case commonv1.Ecosystem_ECOSYSTEM_MAVEN:
		return valueobject.EcosystemMaven
	case commonv1.Ecosystem_ECOSYSTEM_CARGO:
		return valueobject.EcosystemCargo
	case commonv1.Ecosystem_ECOSYSTEM_RUBYGEMS:
		return valueobject.EcosystemRubyGems
	case commonv1.Ecosystem_ECOSYSTEM_NUGET:
		return valueobject.EcosystemNuGet
	case commonv1.Ecosystem_ECOSYSTEM_PACKAGIST:
		return valueobject.EcosystemPackagist
	default:
		return valueobject.EcosystemUnknown
	}
}

func toScores(scores []*commonv1.Cvss) []model.CVSS {
	out := make([]model.CVSS, 0, len(scores))
	for _, s := range scores {
		out = append(out, model.CVSS{
			Version:   s.GetVersion(),
			BaseScore: s.GetBaseScore(),
			Vector:    s.GetVector(),
			Severity:  toSeverity(s.GetSeverity()),
		})
	}
	return out
}

func toSeverity(s commonv1.Severity) model.Severity {
	switch s {
	case commonv1.Severity_SEVERITY_NONE:
		return model.SeverityNone
	case commonv1.Severity_SEVERITY_LOW:
		return model.SeverityLow
	case commonv1.Severity_SEVERITY_MEDIUM:
		return model.SeverityMedium
	case commonv1.Severity_SEVERITY_HIGH:
		return model.SeverityHigh
	case commonv1.Severity_SEVERITY_CRITICAL:
		return model.SeverityCritical
	default:
		return model.SeverityUnknown
	}
}

func sourcesFrom(k eventsv1.SourceKind) []string {
	switch k {
	case eventsv1.SourceKind_SOURCE_KIND_NVD:
		return []string{"nvd"}
	case eventsv1.SourceKind_SOURCE_KIND_GITHUB_ADVISORY:
		return []string{"github_advisory"}
	case eventsv1.SourceKind_SOURCE_KIND_CISA_KEV:
		return []string{"cisa_kev"}
	case eventsv1.SourceKind_SOURCE_KIND_EXPLOIT_DB:
		return []string{"exploit_db"}
	case eventsv1.SourceKind_SOURCE_KIND_MITRE:
		return []string{"mitre"}
	case eventsv1.SourceKind_SOURCE_KIND_VENDOR_ADVISORY:
		return []string{"vendor_advisory"}
	case eventsv1.SourceKind_SOURCE_KIND_OSINT:
		return []string{"osint"}
	case eventsv1.SourceKind_SOURCE_KIND_PACKAGE_FEED:
		return []string{"package_feed"}
	case eventsv1.SourceKind_SOURCE_KIND_SHODAN:
		return []string{"shodan"}
	case eventsv1.SourceKind_SOURCE_KIND_GSD:
		return []string{"gsd"}
	default:
		return nil
	}
}

func fromTimestamp(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}
