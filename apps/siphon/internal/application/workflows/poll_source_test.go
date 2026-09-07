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
}

func (c *capturingPublisher) Publish(_ context.Context, evt events.SignalDiscovered) error {
	if c.failOn != "" && evt.Signal.CVEID == c.failOn {
		return errors.New("publish failed")
	}
	c.published = append(c.published, evt)
	return nil
}

var _ = Describe("PollSource use case", func() {
	var (
		ctx = context.Background()
		pub *capturingPublisher
	)

	BeforeEach(func() { pub = &capturingPublisher{} })

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
