package queries_test

import (
	"context"
	"slices"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/queries"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
	vo "github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// exposureGraph serves fixed exposure rows, like the graph adapter.
type exposureGraph struct {
	ports.DependencyGraph
	rows     []model.Exposure
	has      bool
	gotNames []string
	gotDepth int
}

func (g *exposureGraph) FindRepositoryExposures(_ context.Context, names []string, depth int) ([]model.Exposure, error) {
	g.gotNames, g.gotDepth = names, depth
	return slices.Clone(g.rows), nil
}

func (g *exposureGraph) HasRepository(context.Context, string) (bool, error) { return g.has, nil }

// findingsStub is the store of record, keyed by any id.
type findingsStub []model.Vulnerability

func (f findingsStub) FindByIDs(_ context.Context, ids []string) ([]model.Vulnerability, error) {
	var out []model.Vulnerability
	for _, v := range f {
		if slices.ContainsFunc(v.IDs(), func(id string) bool { return slices.Contains(ids, id) }) {
			out = append(out, v)
		}
	}
	return out, nil
}

func exposureRow(repo, id, library, declared, affected string) model.Exposure {
	return model.Exposure{
		Repository:       repo,
		Finding:          model.Vulnerability{CVEID: id},
		Package:          vo.PackageRef{Ecosystem: vo.EcosystemNPM, Name: library, Version: declared},
		AffectedVersions: affected,
		Depth:            1,
		Direct:           true,
	}
}

func rated(id, title string, sev model.Severity) model.Vulnerability {
	return model.Vulnerability{CVEID: id, Title: title, Kind: model.KindVulnerability, Scores: []model.CVSS{{Severity: sev}}}
}

var _ = Describe("RepositoryExposure", func() {
	const repo = "InventedSarawak/CacheMiss"
	ctx := context.Background()

	store := findingsStub{
		rated("CVE-2024-56159", "Astro source exposed via sourcemaps", model.SeverityHigh),
		rated("CVE-2025-54793", "Astro open redirect", model.SeverityMedium),
		rated("CVE-2019-10744", "lodash prototype pollution", model.SeverityCritical),
		{CVEID: "GHSA-fw8c-xr5c-95f9", Aliases: []string{"MAL-2026-2307"}, Kind: model.KindMalware, Title: "Malicious code in axios"},
	}
	rows := func() []model.Exposure {
		return []model.Exposure{
			exposureRow(repo, "CVE-2024-56159", "astro", "^5.11.0", "< 5.0.8"),
			exposureRow(repo, "CVE-2025-54793", "astro", "^5.11.0", ">= 5.2.0, < 5.12.8"),
			exposureRow(repo, "CVE-2019-10744", "lodash", "4.17.4", "< 4.17.12"),
			exposureRow(repo, "GHSA-fw8c-xr5c-95f9", "axios", "^1.14.0", "= 0.30.4 || = 1.14.1"),
		}
	}
	ids := func(es []model.Exposure) []string {
		out := []string{}
		for _, e := range es {
			out = append(out, e.Finding.CVEID)
		}
		return out
	}

	It("judges each finding by version and lists what the repository is exposed to, worst first", func() {
		graph := &exposureGraph{rows: rows()}
		got, err := queries.NewRepositoryExposure(graph, store, 0).Handle(ctx, repo, 0, false)

		Expect(err).ToNot(HaveOccurred())
		Expect(got.Scanned).To(BeTrue())
		Expect(graph.gotDepth).To(Equal(queries.DefaultBlastRadiusDepth))
		// Affected before possibly affected; within that, malware counts as critical.
		Expect(ids(got.Findings)).To(Equal([]string{"CVE-2019-10744", "GHSA-fw8c-xr5c-95f9", "CVE-2025-54793"}))
		Expect(got.Findings[0].Verdict).To(Equal(vo.ExposureAffected))
		Expect(got.Findings[0].Finding.Title).To(Equal("lodash prototype pollution"), "filled in from the store")
		Expect(got.Findings[1].Verdict).To(Equal(vo.ExposurePossible))
		Expect(ids(got.Findings)).ToNot(ContainElement("CVE-2024-56159"), "astro ^5.11.0 is past its range")
	})

	It("keeps what the versions rule out when asked, marked and last", func() {
		got, err := queries.NewRepositoryExposure(&exposureGraph{rows: rows()}, store, 0).Handle(ctx, repo, 0, true)

		Expect(err).ToNot(HaveOccurred())
		last := got.Findings[len(got.Findings)-1]
		Expect(last.Finding.CVEID).To(Equal("CVE-2024-56159"))
		Expect(last.Verdict).To(Equal(vo.ExposureNotAffected))
	})

	It("flags the repository by its serious findings, whether or not the list shows the rest", func() {
		got, err := queries.NewRepositoryExposure(&exposureGraph{rows: rows()}, store, 0).Handle(ctx, repo, 0, false)

		Expect(err).ToNot(HaveOccurred())
		Expect(got.Summary).To(Equal(model.ExposureSummary{
			Computed:         true,
			CriticalAffected: 1, // lodash, pinned inside the range
			CriticalPossible: 1, // the axios malware, which ^1.14.0 may install
			Total:            3, // the high-rated astro finding is ruled out by version
		}))
	})

	It("counts a finding reached through two libraries once, at its worst verdict", func() {
		graph := &exposureGraph{rows: []model.Exposure{
			exposureRow(repo, "CVE-2019-10744", "lodash-es", "4.17.21", "< 4.17.12"),
			exposureRow(repo, "CVE-2019-10744", "lodash", "4.17.4", "< 4.17.12"),
		}}
		got, err := queries.NewRepositoryExposure(graph, store, 0).Handle(ctx, repo, 0, false)

		Expect(err).ToNot(HaveOccurred())
		Expect(got.Summary.Total).To(Equal(1))
		Expect(got.Summary.CriticalAffected).To(Equal(1))
	})

	It("says a repository the graph has never seen is unscanned, not clean", func() {
		got, err := queries.NewRepositoryExposure(&exposureGraph{}, store, 0).Handle(ctx, "someone/else", 0, false)
		Expect(err).ToNot(HaveOccurred())
		Expect(got.Scanned).To(BeFalse())

		got, err = queries.NewRepositoryExposure(&exposureGraph{has: true}, store, 0).Handle(ctx, "someone/clean", 0, false)
		Expect(err).ToNot(HaveOccurred())
		Expect(got.Scanned).To(BeTrue(), "in the graph, with nothing reachable")
		Expect(got.Findings).To(BeEmpty())
	})

	It("needs a repository and a graph", func() {
		_, err := queries.NewRepositoryExposure(&exposureGraph{}, store, 0).Handle(ctx, "  ", 0, false)
		Expect(err).To(MatchError(queries.ErrNeedRepository))

		_, err = queries.NewRepositoryExposure(nil, store, 0).Handle(ctx, repo, 0, false)
		Expect(err).To(MatchError(ports.ErrGraphUnavailable))
	})

	It("summarizes every repository in the graph, keyed by lower-cased name", func() {
		all := append(rows(), exposureRow("vercel/commerce", "CVE-2019-10744", "lodash", "4.17.4", "< 4.17.12"))
		got, err := queries.NewRepositoryExposure(&exposureGraph{rows: all}, store, 0).Summaries(ctx)

		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(HaveKey("inventedsarawak/cachemiss"))
		Expect(got["vercel/commerce"].CriticalAffected).To(Equal(1))
	})
})
