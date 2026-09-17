package model_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// kernel builds one of the Linux kernel CNA's findings: the same opening
// sentence every time, an unscored finding, and a tail that differs.
func kernel(n int, tail string) model.SearchHit {
	return model.SearchHit{Vulnerability: model.Vulnerability{
		CVEID:       fmt.Sprintf("CVE-2026-%05d", n),
		Description: "In the Linux kernel, the following vulnerability has been resolved: " + tail,
	}}
}

// scored builds an ordinary finding with its own wording and a rating.
func scored(id, title, severity string) model.SearchHit {
	return model.SearchHit{Vulnerability: model.Vulnerability{
		CVEID:  id,
		Title:  title,
		Scores: []model.CVSS{{BaseScore: 9.8, Severity: severity}},
	}}
}

func run(n int) []model.SearchHit { return runFrom(90000, n) }

// runFrom builds a run starting at a given id. Feed.Append dedupes on the CVE
// id, so no two findings in a real feed share one.
func runFrom(start, n int) []model.SearchHit {
	hits := make([]model.SearchHit, 0, n)
	for i := range n {
		hits = append(hits, kernel(start+i, fmt.Sprintf("driver %d leaks a reference", i)))
	}
	return hits
}

var _ = Describe("Feed batching", func() {
	open := map[string]bool{}

	It("folds a run of six or more into one row", func() {
		feed := model.Feed{Hits: run(200)}

		rows := feed.Rows(open)
		Expect(rows).To(HaveLen(1))
		Expect(rows[0].IsBatch()).To(BeTrue())
		Expect(rows[0].Batch.Len()).To(Equal(200))
		Expect(rows[0].Batch.Signature).To(HavePrefix("in the linux kernel, the following vulnerability has been resolved"))
	})

	It("leaves a run of five alone", func() {
		// The user's line: fold only what actually costs a screen. Five
		// rows read fine, and a fold over them is more chrome than it saves.
		feed := model.Feed{Hits: run(5)}

		rows := feed.Rows(open)
		Expect(rows).To(HaveLen(5))
		for _, r := range rows {
			Expect(r.IsBatch()).To(BeFalse())
		}
	})

	It("folds at exactly six", func() {
		Expect(model.Feed{Hits: run(6)}.Rows(open)).To(HaveLen(1))
	})

	It("keeps findings outside the run on their own rows", func() {
		hits := append([]model.SearchHit{scored("CVE-2026-1", "log4shell", "CRITICAL")}, run(20)...)
		hits = append(hits, scored("CVE-2026-2", "a totally unrelated advisory", "HIGH"))

		rows := model.Feed{Hits: hits}.Rows(open)
		Expect(rows).To(HaveLen(3))
		Expect(rows[0].Vulnerability.CVEID).To(Equal("CVE-2026-1"))
		Expect(rows[1].IsBatch()).To(BeTrue())
		Expect(rows[2].Vulnerability.CVEID).To(Equal("CVE-2026-2"))
	})

	It("opens the run in place when expanded", func() {
		feed := model.Feed{Hits: run(10)}
		key := feed.Rows(open)[0].Batch.Key

		rows := feed.Rows(map[string]bool{key: true})
		Expect(rows).To(HaveLen(11))
		Expect(rows[0].IsBatch()).To(BeTrue())
		for _, r := range rows[1:] {
			Expect(r.IsBatch()).To(BeFalse())
			Expect(r.Nested).To(BeTrue())
		}
	})

	It("reports the worst rating inside, so a fold buries nothing", func() {
		hits := run(20)
		hits[7].Vulnerability.Scores = []model.CVSS{{BaseScore: 8.8, Severity: "HIGH"}}

		batch := model.Feed{Hits: hits}.Rows(open)[0].Batch
		Expect(batch.Worst()).To(Equal("HIGH"))
		Expect(batch.Breakdown()).To(Equal("high 1 · unknown 19"))
	})

	It("rates a batch of malware above any severity", func() {
		hits := run(8)
		hits[3].Vulnerability.Kind = model.KindMalware

		Expect(model.Feed{Hits: hits}.Rows(open)[0].Batch.Worst()).To(Equal(model.LabelMalware))
	})

	It("does not group findings that merely share a word or two", func() {
		var hits []model.SearchHit
		for i := range 10 {
			hits = append(hits, scored(fmt.Sprintf("CVE-2026-%d", i),
				fmt.Sprintf("a vulnerability in thing number %d", i), "HIGH"))
		}
		// "a vulnerability in thing number" is five shared words, which is
		// the threshold — the differing count is the sixth.
		rows := model.Feed{Hits: hits}.Rows(open)
		Expect(rows).To(HaveLen(1), "a shared five-word template is still a template")

		for i := range hits {
			hits[i].Vulnerability.Title = fmt.Sprintf("a flaw %d was found in some library", i)
		}
		rows = model.Feed{Hits: hits}.Rows(open)
		Expect(rows).To(HaveLen(10), "wording that diverges at the second word is not a batch")
	})

	It("opens one run without opening another of the same wording", func() {
		// The kernel CNA files several runs a day, separated by everyone
		// else's findings — the newest thousand findings hold six of them.
		// Opening one must not open all six, which is the flood the fold is
		// there to prevent.
		hits := append(runFrom(90000, 10), scored("CVE-2026-X", "an unrelated advisory", "HIGH"))
		hits = append(hits, runFrom(80000, 10)...)
		feed := model.Feed{Hits: hits}

		rows := feed.Rows(open)
		Expect(rows).To(HaveLen(3))
		first, second := rows[0].Batch, rows[2].Batch
		Expect(first.Signature).To(Equal(second.Signature))
		Expect(first.Key).ToNot(Equal(second.Key))

		rows = feed.Rows(map[string]bool{first.Key: true})
		Expect(rows).To(HaveLen(13), "only the first run opened")
		Expect(rows[11].IsBatch()).To(BeFalse())
		Expect(rows[12].IsBatch()).To(BeTrue())
	})

	It("finds a row by CVE only when it is actually on screen", func() {
		feed := model.Feed{Hits: run(10)}
		rows := feed.Rows(open)
		Expect(feed.RowIndexOf(rows, "CVE-2026-90003")).To(Equal(-1), "inside a closed fold")

		key := rows[0].Batch.Key
		rows = feed.Rows(map[string]bool{key: true})
		Expect(feed.RowIndexOf(rows, "CVE-2026-90003")).To(Equal(4))
	})
})
