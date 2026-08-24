// Package consumer is an INBOUND adapter: it reads SignalDiscovered events as
// protojson lines (siphon's stdout piped to cortex's stdin) and drives the
// ingest use case. This is cortex's proto boundary — the only inbound place
// that touches the generated contract types.
package consumer

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/common/v1"
	eventsv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/events/v1"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
)

const maxLineBytes = 4 * 1024 * 1024 // events can be large (many references)

// Ingester is the use case this adapter drives (consumer-side interface).
type Ingester interface {
	Handle(ctx context.Context, v model.Vulnerability) error
}

// Consumer reads protojson events from an io.Reader and ingests each one.
type Consumer struct {
	ingester Ingester
	log      *slog.Logger
}

// NewConsumer wires the adapter to the ingest use case.
func NewConsumer(ingester Ingester) *Consumer {
	return &Consumer{ingester: ingester, log: slog.Default()}
}

// Run consumes lines until EOF (or ctx cancellation), returning how many events
// were ingested. Malformed lines and per-event ingest errors are logged and
// skipped so one bad record can't halt the stream.
func (c *Consumer) Run(ctx context.Context, r io.Reader) (int, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)

	processed := 0
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return processed, ctx.Err()
		default:
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

		v := toDomain(&msg)
		if err := c.ingester.Handle(ctx, v); err != nil {
			c.log.Error("ingest failed", "cve", v.CVEID, "error", err)
			continue
		}
		processed++
	}
	if err := scanner.Err(); err != nil {
		return processed, fmt.Errorf("consumer: scan: %w", err)
	}
	return processed, nil
}

// --- mapping: wire contract -> cortex domain ---

func toDomain(msg *eventsv1.SignalDiscovered) model.Vulnerability {
	v := msg.GetVulnerability()
	return model.Vulnerability{
		CVEID:       v.GetCveId(),
		Title:       v.GetTitle(),
		Description: v.GetDescription(),
		Scores:      toScores(v.GetScores()),
		References:  v.GetReferences(),
		Sources:     sourcesFrom(msg.GetSource()),
		PublishedAt: fromTimestamp(v.GetPublishedAt()),
		ModifiedAt:  fromTimestamp(v.GetModifiedAt()),
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
