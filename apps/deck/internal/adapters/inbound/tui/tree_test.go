package tui_test

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/adapters/inbound/tui"
	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

var _ = Describe("Graph explorer tree", func() {
	It("draws the vulnerability, its packages and the repositories beneath them", func() {
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

		out := tui.RenderTree(radius)
		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")

		Expect(lines[0]).To(Equal("CVE-2021-44228"))
		Expect(lines[1]).To(Equal("└── maven:log4j-core"))
		Expect(lines[2]).To(Equal("    ├── acme/api  (direct)"))
		Expect(lines[3]).To(Equal("    └── acme/web  (2 hops)"))
		// Only the multi-hop repository gets a chain line; the direct one
		// would just be repeating itself.
		Expect(lines[4]).To(Equal("        └── acme/web → maven:framework → maven:log4j-core"))
		Expect(lines).To(HaveLen(5))
	})

	It("says the radius is unknown when the CVE has no package linkage", func() {
		// An unlinked CVE must never render as "0 repositories exposed".
		out := tui.RenderTree(model.BlastRadius{CVEID: "CVE-2021-44228"})

		Expect(out).To(ContainSubstring("blast radius unknown"))
		Expect(out).ToNot(ContainSubstring("0 repositories"))
	})

	It("reports a named package that nothing depends on", func() {
		out := tui.RenderTree(model.BlastRadius{
			CVEID:              "CVE-2021-44228",
			VulnerablePackages: []string{"maven:log4j-core"},
		})

		Expect(out).To(ContainSubstring("no tracked repository depends on this"))
	})

	It("lists packages with exposure before those without", func() {
		out := tui.RenderTree(model.BlastRadius{
			CVEID:              "CVE-1",
			VulnerablePackages: []string{"npm:unused", "npm:used"},
			Repositories: []model.ImpactedRepository{
				{FullName: "acme/api", ViaPackage: "npm:used", Depth: 1, Direct: true},
			},
		})

		Expect(strings.Index(out, "npm:used")).To(BeNumerically("<", strings.Index(out, "npm:unused")))
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
	})

	It("draws trunk lines so nested branches stay readable", func() {
		out := tui.RenderTree(model.BlastRadius{
			CVEID:              "CVE-1",
			VulnerablePackages: []string{"npm:a", "npm:b"},
			Repositories: []model.ImpactedRepository{
				{FullName: "acme/one", ViaPackage: "npm:a", Depth: 1, Direct: true},
				{FullName: "acme/two", ViaPackage: "npm:b", Depth: 1, Direct: true},
			},
		})

		Expect(out).To(ContainSubstring("├── npm:a"))
		Expect(out).To(ContainSubstring("│   └── acme/one"))
		Expect(out).To(ContainSubstring("└── npm:b"))
		Expect(out).To(ContainSubstring("    └── acme/two"))
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
