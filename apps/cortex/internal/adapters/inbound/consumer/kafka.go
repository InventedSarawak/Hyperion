package consumer

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/inventedsarawak/hyperion/packages/common/kafka"
	eventsv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/events/v1"
)

// KafkaHandler ingests SignalDiscovered records from the signal topic. It is
// the same inbound boundary as the stdin Consumer — decode the contract type,
// map it onto the domain, drive the ingest use case — reached over a broker
// instead of a pipe, and it reuses that mapping rather than repeating it.
//
// There is no worker pool here, because the transport already provides one.
// The stdin consumer shards events across workers by finding id so that two
// reports of one CVE are never merged at once; on Kafka that is the partition
// key, and the consumer runs one goroutine per partition. The invariant is the
// same; it is enforced a level lower.
type KafkaHandler struct {
	ingester Ingester
	log      *slog.Logger

	progressEvery int64
	processed     atomic.Int64
	started       time.Time
}

// NewKafkaHandler wires the adapter to the ingest use case. progressEvery is
// how many ingested findings pass between progress lines; zero silences them.
func NewKafkaHandler(ingester Ingester, progressEvery int, log *slog.Logger) *KafkaHandler {
	if log == nil {
		log = slog.Default()
	}
	if progressEvery < 0 {
		progressEvery = 0
	}
	return &KafkaHandler{
		ingester:      ingester,
		log:           log,
		progressEvery: int64(progressEvery),
		started:       time.Now(),
	}
}

// Handle ingests one record.
//
// The two failures are answered differently, and the difference is the whole
// contract with the consumer. A record that will not decode is unprocessable:
// Message.Into says so, the consumer skips it and commits past it, because
// retrying it forever would stop every later record on that partition. An
// ingest failure is the world being temporarily broken — Postgres refusing a
// write — so it is returned plainly, retried, and if it still fails the
// consumer stops without committing. Those records are then replayed on the
// next start rather than silently lost.
func (h *KafkaHandler) Handle(ctx context.Context, msg kafka.Message) error {
	var evt eventsv1.SignalDiscovered
	if err := msg.Into(&evt); err != nil {
		return err
	}

	v := toDomain(&evt)
	if err := h.ingester.Handle(ctx, v); err != nil {
		return err
	}

	done := h.processed.Add(1)
	h.log.Debug("ingested", "id", v.CVEID, "kind", v.Kind,
		"packages", len(v.AffectedPackages), "sources", v.Sources,
		"partition", msg.Partition, "offset", msg.Offset)

	// A heartbeat rather than a line per finding: a firehose is hundreds of
	// thousands of them, and what a reader needs to know is that it is moving,
	// and how fast.
	if h.progressEvery > 0 && done%h.progressEvery == 0 {
		h.log.Info("ingest progress",
			"ingested", done,
			"per_second", int64(float64(done)/time.Since(h.started).Seconds()),
			"latest", v.CVEID)
	}
	return nil
}

// Processed reports how many findings this handler has ingested.
func (h *KafkaHandler) Processed() int64 { return h.processed.Load() }
