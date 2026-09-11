package tui_test

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/adapters/inbound/tui"
	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

var _ = Describe("Graph explorer tree", func() {
	It("puts each repository at the top, with the path down to the finding beneath it", func() {
		radius := model.BlastRadius{
			CVEID:              "CVE-2021-44228",
			VulnerablePackages: []string{"maven:log4j-core"},
			Repositories: []model.ImpactedRepository{
				{FullName: "acme/api", ViaPackage: "maven:log4j-core", Depth: 1, Direct: true,
					Path: []string{"acme/api", "maven:log4j-core"}},
				{FullName: "acme/web", ViaPackage: "maven:log4j-core", Depth: 2,
					Path: []string{"acme/web", "maven:framework", "maven:log4j-core"}},
			},
		}

		lines := strings.Split(strings.TrimRight(tui.RenderTree(radius), "\n"), "\n")

		Expect(lines).To(Equal([]string{
			"acme/api  (direct)",
			"└── maven:log4j-core",
			"    └── CVE-2021-44228",
			"",
			"acme/web  (2 hops)",
			"└── maven:framework",
			"    └── maven:log4j-core",
			"        └── CVE-2021-44228",
		}))
	})

	It("falls back to the package reached when there is no path", func() {
		out := tui.RenderTree(model.BlastRadius{
			CVEID:              "CVE-1",
			VulnerablePackages: []string{"npm:next"},
			Repositories:       []model.ImpactedRepository{{FullName: "acme/api", ViaPackage: "npm:next", Depth: 1, Direct: true}},
		})
		Expect(out).To(Equal("acme/api  (direct)\n└── npm:next\n    └── CVE-1\n"))
	})

	It("says the radius is unknown when the CVE has no package linkage", func() {
		// An unlinked CVE must never render as "0 repositories exposed".
		out := tui.RenderTree(model.BlastRadius{CVEID: "CVE-2021-44228"})

		Expect(out).To(ContainSubstring("blast radius unknown"))
		Expect(out).ToNot(ContainSubstring("0 repositories"))
	})

	It("lists the named packages no tracked repository reaches, after those it does", func() {
		out := tui.RenderTree(model.BlastRadius{
			CVEID:              "CVE-1",
			VulnerablePackages: []string{"npm:unused-a", "npm:used", "npm:unused-b"},
			Repositories: []model.ImpactedRepository{
				{FullName: "acme/api", ViaPackage: "npm:used", Depth: 1, Direct: true},
			},
		})

		Expect(out).To(HaveSuffix("not reached by any tracked repository\n├── npm:unused-a\n└── npm:unused-b\n"))
		Expect(strings.Index(out, "acme/api")).To(BeNumerically("<", strings.Index(out, "not reached")))
	})

	It("reports every named package as unreached when nothing depends on them", func() {
		out := tui.RenderTree(model.BlastRadius{
			CVEID:              "CVE-2021-44228",
			VulnerablePackages: []string{"maven:log4j-core"},
		})

		Expect(out).To(Equal("not reached by any tracked repository\n└── maven:log4j-core\n"))
	})

	It("still shows a repository reached through a package the advisory did not name", func() {
		out := tui.RenderTree(model.BlastRadius{
			CVEID:              "CVE-1",
			VulnerablePackages: []string{"npm:named"},
			Repositories: []model.ImpactedRepository{
				{FullName: "acme/api", ViaPackage: "npm:unnamed", Depth: 1, Direct: true},
			},
		})

		Expect(out).To(ContainSubstring("npm:unnamed"))
		Expect(out).To(ContainSubstring("acme/api"))
		Expect(out).To(ContainSubstring("└── npm:named"), "the named package is still listed as unreached")
	})

	It("handles an empty radius without panicking", func() {
		Expect(tui.RenderTree(model.BlastRadius{})).To(ContainSubstring("no vulnerability selected"))
	})
})

var _ = Describe("Vulnerability view model", func() {
	It("shows the worst score when feeds disagree", func() {
		v := model.Vulnerability{Scores: []model.CVSS{
			{BaseScore: 5.3, Severity: "MEDIUM"},
			{BaseScore: 10.0, Severity: "CRITICAL"},
		}}
		top, ok := v.TopScore()
		Expect(ok).To(BeTrue())
		Expect(top.BaseScore).To(Equal(10.0))
		Expect(v.SeverityLabel()).To(Equal("CRITICAL"))
	})

	It("derives a label from the score when the feed gave none", func() {
		Expect(model.Vulnerability{Scores: []model.CVSS{{BaseScore: 7.5}}}.SeverityLabel()).To(Equal("HIGH"))
		Expect(model.Vulnerability{Scores: []model.CVSS{{BaseScore: 4.0}}}.SeverityLabel()).To(Equal("MEDIUM"))
		Expect(model.Vulnerability{Scores: []model.CVSS{{BaseScore: 0.5}}}.SeverityLabel()).To(Equal("LOW"))
	})

	It("says UNKNOWN rather than guessing when there is no score at all", func() {
		Expect(model.Vulnerability{}.SeverityLabel()).To(Equal("UNKNOWN"))
	})

	It("falls back through title, description, then id for the headline", func() {
		Expect(model.Vulnerability{CVEID: "CVE-1", Title: "Log4Shell"}.Headline()).To(Equal("Log4Shell"))
		Expect(model.Vulnerability{CVEID: "CVE-1", Description: "RCE"}.Headline()).To(Equal("RCE"))
		Expect(model.Vulnerability{CVEID: "CVE-1"}.Headline()).To(Equal("CVE-1"))
	})
})
