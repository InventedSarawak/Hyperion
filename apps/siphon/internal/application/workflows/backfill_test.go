package workflows_test

import (
	"context"
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/application/workflows"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/ports"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// fakeBackfiller hands its batches to emit, in order.
type fakeBackfiller struct {
	kind    valueobject.SourceKind
	batches [][]model.SourceSignal
	err     error
	from    time.Time
}

func (f *fakeBackfiller) Kind() valueobject.SourceKind { return f.kind }
func (f *fakeBackfiller) Backfill(_ context.Context, from time.Time, emit func([]model.SourceSignal) error) error {
	f.from = from
	for _, b := range f.batches {
		if err := emit(b); err != nil {
			return err
		}
	}
	return f.err
}

var _ = Describe("Backfill use case", func() {
	var (
		ctx  = context.Background()
		pub  *capturingPublisher
		from = time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)
	)

	BeforeEach(func() { pub = &capturingPublisher{} })

	It("publishes every batch from every source, attributed to its source", func() {
		nvd := &fakeBackfiller{kind: valueobject.SourceKindNVD, batches: [][]model.SourceSignal{
			{{CVEID: "CVE-2016-0001"}, {CVEID: "CVE-2016-0002"}},
			{{CVEID: "CVE-2020-0001"}},
		}}
		osv := &fakeBackfiller{kind: valueobject.SourceKindPackageFeed, batches: [][]model.SourceSignal{
			{{CVEID: "GHSA-fw8c-xr5c-95f9"}, {CVEID: ""}}, // the invalid one is skipped
		}}

		n, err := workflows.NewBackfill([]ports.Backfiller{nvd, osv}, pub).Run(ctx, from)

		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(4))
		Expect(nvd.from).To(Equal(from))
		Expect(pub.published).To(HaveLen(4))
		Expect(pub.published[0].Source).To(Equal(valueobject.SourceKindNVD))
		Expect(pub.published[3].Source).To(Equal(valueobject.SourceKindPackageFeed))
		Expect(pub.published[3].SignalID).To(Equal("package_feed:GHSA-fw8c-xr5c-95f9"))
	})

	It("keeps going past a source that fails, and reports it", func() {
		broken := &fakeBackfiller{kind: valueobject.SourceKindNVD,
			batches: [][]model.SourceSignal{{{CVEID: "CVE-2016-0001"}}}, err: errors.New("nvd down")}
		healthy := &fakeBackfiller{kind: valueobject.SourceKindPackageFeed,
			batches: [][]model.SourceSignal{{{CVEID: "CVE-2025-55182"}}}}

		n, err := workflows.NewBackfill([]ports.Backfiller{broken, healthy}, pub).Run(ctx, from)

		Expect(err).To(MatchError(ContainSubstring("nvd down")))
		Expect(n).To(Equal(2), "what the broken source did produce is still published")
	})

	It("stops everything when publishing fails, since nothing is listening", func() {
		pub.failOn = "CVE-2016-0001"
		first := &fakeBackfiller{kind: valueobject.SourceKindNVD,
			batches: [][]model.SourceSignal{{{CVEID: "CVE-2016-0001"}}}}
		second := &fakeBackfiller{kind: valueobject.SourceKindPackageFeed,
			batches: [][]model.SourceSignal{{{CVEID: "CVE-2025-55182"}}}}

		_, err := workflows.NewBackfill([]ports.Backfiller{first, second}, pub).Run(ctx, from)

		Expect(err).To(MatchError(ContainSubstring("publish failed")))
		Expect(second.from).To(BeZero(), "the second source is never started")
	})
})
