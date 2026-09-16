package workflows_test

import (
	"context"
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/application/workflows"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/events"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// fakeSource is a stand-in SourceClient (outbound port) — no network.
type fakeSource struct {
	kind    valueobject.SourceKind
	signals []model.SourceSignal
	err     error
}

func (f *fakeSource) Kind() valueobject.SourceKind { return f.kind }
func (f *fakeSource) Fetch(context.Context, time.Time) ([]model.SourceSignal, error) {
	return f.signals, f.err
}

// capturingPublisher is a stand-in SignalPublisher (outbound port) — records
// what would have been published, and can be told to fail on a given CVE id.
type capturingPublisher struct {
	published []events.SignalDiscovered
	failOn    string
	// flushErr, when set, fails the flush that ends a run — the case where
	// every event was accepted but the broker never confirmed them.
	flushErr error
	flushes  int
}

func (c *capturingPublisher) Publish(_ context.Context, evt events.SignalDiscovered) error {
	if c.failOn != "" && evt.Signal.CVEID == c.failOn {
		return errors.New("publish failed")
	}
	c.published = append(c.published, evt)
	return nil
}

func (c *capturingPublisher) Flush(context.Context) error {
	c.flushes++
	return c.flushErr
}

// fakeDedupe is a stand-in DedupeStore (outbound port). It reports each
// fingerprint as new exactly once, which is what a real store does.
type fakeDedupe struct {
	seen map[string]bool
	err  error
	// calls counts FirstSeen calls, to prove suppression happened at the
	// workflow rather than by accident downstream.
	calls int
}

func newFakeDedupe() *fakeDedupe { return &fakeDedupe{seen: map[string]bool{}} }

func (f *fakeDedupe) FirstSeen(_ context.Context, key string, _ time.Duration) (bool, error) {
	f.calls++
	if f.err != nil {
		return false, f.err
	}
	if f.seen[key] {
		return false, nil
	}
	f.seen[key] = true
	return true, nil
}

var _ = Describe("PollSource dedupe", func() {
	var (
		ctx    = context.Background()
		pub    *capturingPublisher
		seen   *fakeDedupe
		signal = model.SourceSignal{CVEID: "CVE-2021-44228", Title: "Log4Shell"}
	)

	BeforeEach(func() {
		pub = &capturingPublisher{}
		seen = newFakeDedupe()
	})

	It("publishes an observation the first time and suppresses it after", func() {
		src := &fakeSource{kind: valueobject.SourceKindNVD, signals: []model.SourceSignal{signal}}
		poll := workflows.NewPollSource(src, pub).WithDedupe(seen, time.Hour)

		first, err := poll.Run(ctx, time.Time{})
		Expect(err).NotTo(HaveOccurred())
		Expect(first).To(Equal(1))

		// A poll re-reads its whole window, so the same advisory comes back
		// on the next pass. It should not go out again.
		second, err := poll.Run(ctx, time.Time{})
		Expect(err).NotTo(HaveOccurred())
		Expect(second).To(BeZero())
		Expect(pub.published).To(HaveLen(1))
	})

	It("publishes again when the observation has changed", func() {
		src := &fakeSource{kind: valueobject.SourceKindNVD, signals: []model.SourceSignal{signal}}
		poll := workflows.NewPollSource(src, pub).WithDedupe(seen, time.Hour)
		_, err := poll.Run(ctx, time.Time{})
		Expect(err).NotTo(HaveOccurred())

		// The feed amends the advisory: a score it did not carry before.
		// Suppressing this would mean the correction never reaches cortex.
		corrected := signal
		corrected.Scores = []model.CVSS{{Version: "3.1", BaseScore: 10, Severity: model.SeverityCritical}}
		src.signals = []model.SourceSignal{corrected}

		n, err := poll.Run(ctx, time.Time{})
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(1))
		Expect(pub.published).To(HaveLen(2))
	})

	It("publishes when the store fails, rather than risking a suppressed signal", func() {
		seen.err = errors.New("redis is down")
		src := &fakeSource{kind: valueobject.SourceKindNVD, signals: []model.SourceSignal{signal}}

		n, err := workflows.NewPollSource(src, pub).WithDedupe(seen, time.Hour).Run(ctx, time.Time{})

		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(1))
		Expect(pub.published).To(HaveLen(1))
	})

	It("publishes everything when there is no store at all", func() {
		src := &fakeSource{kind: valueobject.SourceKindNVD, signals: []model.SourceSignal{signal}}
		poll := workflows.NewPollSource(src, pub)

		_, err := poll.Run(ctx, time.Time{})
		Expect(err).NotTo(HaveOccurred())
		_, err = poll.Run(ctx, time.Time{})
		Expect(err).NotTo(HaveOccurred())

		Expect(pub.published).To(HaveLen(2))
		Expect(seen.calls).To(BeZero())
	})

	It("still flushes when every observation was suppressed", func() {
		src := &fakeSource{kind: valueobject.SourceKindNVD, signals: []model.SourceSignal{signal}}
		poll := workflows.NewPollSource(src, pub).WithDedupe(seen, time.Hour)
		_, err := poll.Run(ctx, time.Time{})
		Expect(err).NotTo(HaveOccurred())

		_, err = poll.Run(ctx, time.Time{})

		// The scheduler advances its watermark on a successful poll, and a
		// poll that published nothing is still a successful poll.
		Expect(err).NotTo(HaveOccurred())
		Expect(pub.flushes).To(Equal(2))
	})
})

var _ = Describe("PollSource use case", func() {
	var (
		ctx = context.Background()
		pub *capturingPublisher
	)

	BeforeEach(func() { pub = &capturingPublisher{} })

	It("fails the run when the batch was accepted but never confirmed", func() {
		pub.flushErr = errors.New("broker unreachable")
		src := &fakeSource{
			kind:    valueobject.SourceKindNVD,
			signals: []model.SourceSignal{{CVEID: "CVE-2021-44228"}},
		}

		_, err := workflows.NewPollSource(src, pub).Run(ctx, time.Time{})

		// The scheduler advances its watermark only on success. If an
		// unconfirmed batch reported success, this window would never be
		// fetched again and those findings would be lost.
		Expect(err).To(MatchError(ContainSubstring("flush")))
		Expect(pub.flushes).To(Equal(1))
	})

	It("flushes once the batch is published, so the caller knows it is durable", func() {
		src := &fakeSource{
			kind:    valueobject.SourceKindNVD,
			signals: []model.SourceSignal{{CVEID: "CVE-2021-44228"}},
		}

		_, err := workflows.NewPollSource(src, pub).Run(ctx, time.Time{})

		Expect(err).NotTo(HaveOccurred())
		Expect(pub.flushes).To(Equal(1))
	})

	It("publishes every valid signal and reports the count", func() {
		src := &fakeSource{
			kind: valueobject.SourceKindNVD,
			signals: []model.SourceSignal{
				{CVEID: "CVE-2021-44228"},
				{CVEID: "CVE-2021-45046"},
			},
		}
		n, err := workflows.NewPollSource(src, pub).Run(ctx, time.Time{})

		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(2))
		Expect(pub.published).To(HaveLen(2))
		Expect(pub.published[0].SignalID).To(Equal("nvd:CVE-2021-44228"))
		Expect(pub.published[0].Source).To(Equal(valueobject.SourceKindNVD))
	})

	It("skips invalid signals (missing CVE id) but keeps going", func() {
		src := &fakeSource{
			kind: valueobject.SourceKindNVD,
			signals: []model.SourceSignal{
				{CVEID: ""}, // invalid
				{CVEID: "CVE-2021-44228"},
			},
		}
		n, err := workflows.NewPollSource(src, pub).Run(ctx, time.Time{})

		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(1))
		Expect(pub.published).To(HaveLen(1))
	})

	It("propagates a fetch error", func() {
		src := &fakeSource{kind: valueobject.SourceKindNVD, err: errors.New("upstream down")}

		n, err := workflows.NewPollSource(src, pub).Run(ctx, time.Time{})

		Expect(err).To(HaveOccurred())
		Expect(n).To(Equal(0))
	})

	It("stops on a publish error and returns the count published so far", func() {
		src := &fakeSource{
			kind: valueobject.SourceKindNVD,
			signals: []model.SourceSignal{
				{CVEID: "CVE-1"},
				{CVEID: "CVE-2"}, // publisher will fail here
				{CVEID: "CVE-3"},
			},
		}
		pub.failOn = "CVE-2"

		n, err := workflows.NewPollSource(src, pub).Run(ctx, time.Time{})

		Expect(err).To(HaveOccurred())
		Expect(n).To(Equal(1))
		Expect(pub.published).To(HaveLen(1))
	})
})
