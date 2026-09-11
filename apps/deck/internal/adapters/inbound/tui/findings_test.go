package tui_test

import (
	"context"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mattn/go-runewidth"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/adapters/inbound/tui"
	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// stubFindings serves one repository's findings, hiding the ones its versions
// rule out unless asked, as cortex does.
type stubFindings struct {
	gotName    string
	gotInclude bool
	result     model.RepositoryExposure
}

func (s *stubFindings) Handle(_ context.Context, name string, include bool) (model.RepositoryExposure, error) {
	s.gotName, s.gotInclude = name, include
	out := s.result
	if !include {
		out.Findings = nil
		for _, f := range s.result.Findings {
			if f.Verdict != model.VerdictNotAffected {
				out.Findings = append(out.Findings, f)
			}
		}
	}
	return out, nil
}

var _ = Describe("Repository findings", func() {
	const width, height = 120, 30
	var (
		repos    *stubRepos
		findings *stubFindings
	)

	open := func() tui.Model {
		GinkgoHelper()
		m := tui.New(&stubSearch{feed: feedWith("CVE-1")}, &stubExplorer{},
			tui.Options{Query: "cve", PageSize: 25, Repositories: repos, Findings: findings})
		m, _ = apply(m, tea.WindowSizeMsg{Width: width, Height: height})
		m, cmd := apply(m, key("4"))
		return deliver(m, cmd)
	}
	openFindings := func() tui.Model {
		GinkgoHelper()
		m, cmd := apply(open(), tea.KeyMsg{Type: tea.KeyEnter})
		return deliver(m, cmd)
	}

	BeforeEach(func() {
		now := time.Now()
		repos = &stubRepos{tracked: []model.TrackedRepository{
			{FullName: "InventedSarawak/CacheMiss", Status: model.ScanScanned, DependencyCount: 27, LastScanAt: now,
				Exposure: model.ExposureSummary{Computed: true, CriticalAffected: 1, HighAffected: 4, HighPossible: 2, Total: 25}},
			{FullName: "InventedSarawak/Ledgera", Status: model.ScanScanned, DependencyCount: 10, LastScanAt: now,
				Exposure: model.ExposureSummary{Computed: true, Total: 2}},
			{FullName: "InventedSarawak/Tidy", Status: model.ScanScanned, DependencyCount: 3, LastScanAt: now,
				Exposure: model.ExposureSummary{Computed: true}},
			{FullName: "patelatwork/Nouri", Status: model.ScanScanned, LastScanAt: now},
		}}
		findings = &stubFindings{result: model.RepositoryExposure{
			FullName: "InventedSarawak/CacheMiss", Scanned: true,
			Summary: model.ExposureSummary{Computed: true, CriticalAffected: 1, Total: 2},
			Findings: []model.RepositoryFinding{
				{Vulnerability: model.Vulnerability{CVEID: "GHSA-26w7-cxv4-gfx2", Title: "Astro request forgery",
					Scores: []model.CVSS{{Severity: "CRITICAL"}}},
					Package: "npm:astro", DeclaredVersion: "^5.11.0", AffectedVersions: "< 7.2.8", Verdict: model.VerdictAffected},
				{Vulnerability: model.Vulnerability{CVEID: "CVE-2025-54793", Title: "Astro open redirect",
					Scores: []model.CVSS{{Severity: "MEDIUM"}}},
					Package: "npm:astro", DeclaredVersion: "^5.11.0", AffectedVersions: ">= 5.2.0, < 5.12.8", Verdict: model.VerdictPossiblyAffected},
				{Vulnerability: model.Vulnerability{CVEID: "CVE-2024-56159", Title: "Astro sourcemaps exposed",
					Scores: []model.CVSS{{Severity: "HIGH"}}},
					Package: "npm:astro", DeclaredVersion: "^5.11.0", AffectedVersions: "< 5.0.8", Verdict: model.VerdictNotAffected},
			},
		}}
	})

	It("flags each repository by its serious findings, beside the list", func() {
		view := stripANSI(open().View())

		Expect(view).To(ContainSubstring("RISK"))
		Expect(view).To(MatchRegexp(`InventedSarawak/CacheMiss .*▲ 1 crit 6 high`))
		Expect(view).To(MatchRegexp(`InventedSarawak/Ledgera .*2 lower`))
		Expect(view).To(MatchRegexp(`InventedSarawak/Tidy .*clean`))
		Expect(view).To(MatchRegexp(`patelatwork/Nouri .*—`), "nothing read, so nothing judged")
	})

	It("opens the selected repository's findings, what it is exposed to first", func() {
		m := openFindings()

		Expect(findings.gotName).To(Equal("InventedSarawak/CacheMiss"))
		Expect(findings.gotInclude).To(BeFalse())
		view := stripANSI(m.View())
		Expect(view).To(ContainSubstring("Findings  InventedSarawak/CacheMiss"))
		Expect(view).To(ContainSubstring("critical: 1 affected"))
		Expect(view).To(MatchRegexp(`AFFECTED\s+CRITICAL\s+GHSA-26w7-cxv4-gfx2 npm:astro \^5\.11\.0 → < 7\.2\.8`))
		Expect(view).To(MatchRegexp(`POSSIBLE\s+MEDIUM\s+CVE-2025-54793`))
		Expect(view).ToNot(ContainSubstring("CVE-2024-56159"), "ruled out by version, hidden until asked")
	})

	It("shows what version matching ruled out on u", func() {
		m, cmd := apply(openFindings(), key("u"))
		m = deliver(m, cmd)

		Expect(findings.gotInclude).To(BeTrue())
		Expect(stripANSI(m.View())).To(MatchRegexp(`RULED OUT\s+HIGH\s+CVE-2024-56159`))
	})

	It("goes from a repository to a finding's details, and back", func() {
		m, cmd := apply(openFindings(), tea.KeyMsg{Type: tea.KeyEnter})
		m = deliver(m, cmd)
		view := stripANSI(m.View())
		Expect(view).To(ContainSubstring("▌ 2 Details"))
		Expect(view).To(ContainSubstring("GHSA-26w7-cxv4-gfx2"))

		m, _ = apply(m, key("4"))
		Expect(stripANSI(m.View())).To(ContainSubstring("Findings  InventedSarawak/CacheMiss"), "left where it was")

		m, _ = apply(m, tea.KeyMsg{Type: tea.KeyEsc})
		Expect(stripANSI(m.View())).To(ContainSubstring("REPOSITORY"))
	})

	It("opens a finding straight in the Graph Explorer on b", func() {
		m, _ := apply(openFindings(), key("b"))
		Expect(stripANSI(m.View())).To(ContainSubstring("▌ 3 Graph Explorer"))
	})

	It("says a repository that has not been scanned is unknown, not clean", func() {
		findings.result = model.RepositoryExposure{FullName: "patelatwork/Nouri"}
		m, _ := apply(open(), key("G"))
		m, cmd := apply(m, tea.KeyMsg{Type: tea.KeyEnter})
		m = deliver(m, cmd)

		Expect(findings.gotName).To(Equal("patelatwork/Nouri"))
		Expect(stripANSI(m.View())).To(ContainSubstring("not scanned yet"))
	})

	It("keeps every line of the list and the findings inside the terminal", func() {
		for _, m := range []tui.Model{open(), openFindings()} {
			lines := viewLines(m)
			Expect(len(lines)).To(BeNumerically("<=", height))
			for _, line := range lines {
				Expect(runewidth.StringWidth(line)).To(BeNumerically("<=", width), "%q wraps", line)
			}
		}
	})
})

var _ = Describe("Graph Explorer verdicts", func() {
	It("says beside each repository whether the version it declares is affected", func() {
		out := tui.RenderTree(model.BlastRadius{
			CVEID:              "CVE-2024-56159",
			VulnerablePackages: []string{"npm:astro"},
			Repositories: []model.ImpactedRepository{{
				FullName: "InventedSarawak/CacheMiss", ViaPackage: "npm:astro", Depth: 1, Direct: true,
				DeclaredVersion: "^5.11.0", AffectedVersions: "< 5.0.8", Verdict: model.VerdictNotAffected,
			}},
		})
		Expect(out).To(ContainSubstring("· ruled out by version: declares ^5.11.0, affected < 5.0.8"))
	})
})

// verdictExplorer answers every blast radius with one fixed result.
type verdictExplorer struct{ radius model.BlastRadius }

func (e *verdictExplorer) Handle(context.Context, string, int) (model.BlastRadius, error) {
	return e.radius, nil
}

var _ = Describe("Graph Explorer summary", func() {
	It("does not count a repository its versions rule out as exposed", func() {
		explorer := &verdictExplorer{radius: model.BlastRadius{
			CVEID:              "CVE-2024-56159",
			VulnerablePackages: []string{"npm:astro"},
			Repositories: []model.ImpactedRepository{{
				FullName: "InventedSarawak/CacheMiss", ViaPackage: "npm:astro", Depth: 1, Direct: true,
				DeclaredVersion: "^5.11.0", AffectedVersions: "< 5.0.8", Verdict: model.VerdictNotAffected,
			}},
		}}
		m := tui.New(&stubSearch{feed: feedWith("CVE-2024-56159")}, explorer, tui.Options{Query: "cve", PageSize: 25})
		m, _ = apply(m, tea.WindowSizeMsg{Width: 120, Height: 30})
		m, cmd := apply(m, key("r"))
		m = deliver(m, cmd)
		m, cmd = apply(m, key("b"))
		m = deliver(m, cmd)

		Expect(stripANSI(m.View())).To(ContainSubstring("0 repositories exposed via 1 vulnerable package  ·  1 ruled out by version"))
	})
})
