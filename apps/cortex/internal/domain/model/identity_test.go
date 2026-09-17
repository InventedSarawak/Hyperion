package model_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
)

var _ = Describe("Vulnerability identity", func() {
	It("files a finding under its CVE whichever id the feed led with", func() {
		fromGitHub := model.Vulnerability{CVEID: "GHSA-jfh8-c2jp-5v3q", Aliases: []string{"cve-2021-44228"}}.Normalized()
		fromNVD := model.Vulnerability{CVEID: "CVE-2021-44228"}.Normalized()

		Expect(fromGitHub.CVEID).To(Equal("CVE-2021-44228"))
		Expect(fromGitHub.Aliases).To(Equal([]string{"GHSA-jfh8-c2jp-5v3q"}))
		Expect(fromNVD.CVEID).To(Equal(fromGitHub.CVEID))
	})

	It("keeps a finding with no CVE under its GHSA, then its MAL", func() {
		v := model.Vulnerability{CVEID: "MAL-2026-2307", Aliases: []string{"GHSA-fw8c-xr5c-95f9"}}.Normalized()
		Expect(v.CVEID).To(Equal("GHSA-fw8c-xr5c-95f9"))
		Expect(v.Aliases).To(Equal([]string{"MAL-2026-2307"}))

		v = model.Vulnerability{CVEID: "MAL-2026-9999"}.Normalized()
		Expect(v.CVEID).To(Equal("MAL-2026-9999"))
	})

	It("keeps an unrecognisable id rather than erasing the record's identity", func() {
		v := model.Vulnerability{CVEID: "vendor advisory 7"}.Normalized()
		Expect(v.CVEID).To(Equal("vendor advisory 7"))
	})

	It("lists every id, canonical first", func() {
		v := model.Vulnerability{CVEID: "CVE-2021-44228", Aliases: []string{"GHSA-jfh8-c2jp-5v3q"}}
		Expect(v.IDs()).To(Equal([]string{"CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"}))
	})

	It("does not count any of the ids as a title", func() {
		v := model.Vulnerability{CVEID: "CVE-2021-44228", Aliases: []string{"GHSA-jfh8-c2jp-5v3q"}, Title: "GHSA-jfh8-c2jp-5v3q"}
		Expect(v.HasTitle()).To(BeFalse())
	})
})

var _ = Describe("Vulnerability kind", func() {
	It("defaults to an ordinary vulnerability", func() {
		Expect(model.Vulnerability{CVEID: "CVE-2021-44228"}.Normalized().Kind).To(Equal(model.KindVulnerability))
	})

	It("knows anything with a MAL id is malware, whatever the feed said", func() {
		v := model.Vulnerability{CVEID: "GHSA-fw8c-xr5c-95f9", Aliases: []string{"MAL-2026-2307"}}.Normalized()
		Expect(v.IsMalware()).To(BeTrue())
	})

	It("stays malware once any feed has said so", func() {
		flagged := model.Vulnerability{CVEID: "GHSA-fw8c-xr5c-95f9", Kind: model.KindMalware}.Normalized()
		later := model.Vulnerability{CVEID: "GHSA-fw8c-xr5c-95f9", Kind: model.KindVulnerability}

		Expect(flagged.Merge(later).IsMalware()).To(BeTrue())
		Expect(later.Normalized().Merge(flagged).IsMalware()).To(BeTrue())
	})
})

var _ = Describe("Vulnerability merge across ids", func() {
	It("moves a bare GHSA onto its CVE once a feed reports the two together", func() {
		stored := model.Vulnerability{CVEID: "GHSA-jfh8-c2jp-5v3q", Sources: []string{"github"}}.Normalized()
		incoming := model.Vulnerability{CVEID: "CVE-2021-44228", Aliases: []string{"GHSA-jfh8-c2jp-5v3q"}, Sources: []string{"osv"}}.Normalized()

		merged := stored.Merge(incoming)
		Expect(merged.CVEID).To(Equal("CVE-2021-44228"))
		Expect(merged.Aliases).To(Equal([]string{"GHSA-jfh8-c2jp-5v3q"}))
		Expect(merged.Sources).To(ConsistOf("github", "osv"))
	})

	It("never loses an id either side knew", func() {
		a := model.Vulnerability{CVEID: "CVE-2021-44228", Aliases: []string{"GHSA-jfh8-c2jp-5v3q"}}.Normalized()
		b := model.Vulnerability{CVEID: "CVE-2021-44228", Aliases: []string{"GO-2022-0001"}}.Normalized()
		Expect(a.Merge(b).IDs()).To(ConsistOf("CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q", "GO-2022-0001"))
	})
})

var _ = Describe("Merge choosing between feeds", func() {
	nvd := func(desc string) model.Vulnerability {
		return model.Vulnerability{
			CVEID: "CVE-2021-44228", Description: desc, Sources: []string{"nvd"},
			Scores: []model.CVSS{{Version: "3.1", BaseScore: 10, Severity: model.SeverityCritical}},
		}
	}
	github := func(desc string) model.Vulnerability {
		return model.Vulnerability{
			CVEID: "CVE-2021-44228", Description: desc, Sources: []string{"github_advisory"},
			Scores: []model.CVSS{{Version: "3.1", BaseScore: 9.8, Severity: model.SeverityCritical}},
		}
	}

	It("keeps the better description whichever order the feeds arrive in", func() {
		// The same two observations merged both ways round. Which prose a
		// reader sees should not depend on which feed polled last.
		githubFirst := github("full write-up").Merge(nvd("one paragraph"))
		nvdFirst := nvd("one paragraph").Merge(github("full write-up"))

		Expect(githubFirst.Description).To(Equal("full write-up"))
		Expect(nvdFirst.Description).To(Equal("full write-up"))
	})

	It("keeps the more authoritative scores whichever order they arrive in", func() {
		githubFirst := github("x").Merge(nvd("y"))
		nvdFirst := nvd("y").Merge(github("x"))

		// NVD's vectors are assigned by NIST analysts and are what most
		// tooling quotes.
		Expect(githubFirst.Scores[0].BaseScore).To(Equal(10.0))
		Expect(nvdFirst.Scores[0].BaseScore).To(Equal(10.0))
	})

	It("lets a feed correct itself", func() {
		stored := github("first attempt").Merge(nvd("summary"))

		corrected := stored.Merge(github("corrected write-up"))

		// Refusing a source's own update would freeze the first thing it ever
		// said about the finding.
		Expect(corrected.Description).To(Equal("corrected write-up"))
	})

	It("records which feed each value came from", func() {
		merged := nvd("summary").Merge(github("full write-up"))

		Expect(merged.DescriptionSource).To(Equal("github_advisory"))
		Expect(merged.ScoresSource).To(Equal("nvd"))
	})

	It("replaces an unattributed value with an attributed one", func() {
		// Everything stored before the attribution existed looks like this.
		legacy := model.Vulnerability{CVEID: "CVE-2021-44228", Description: "old text"}

		merged := legacy.Merge(nvd("summary"))

		Expect(merged.Description).To(Equal("summary"))
		Expect(merged.DescriptionSource).To(Equal("nvd"))
	})

	It("does not lose a description to a feed that has none", func() {
		stored := github("full write-up")

		merged := stored.Merge(model.Vulnerability{CVEID: "CVE-2021-44228", Sources: []string{"nvd"}})

		Expect(merged.Description).To(Equal("full write-up"))
	})
})

var _ = Describe("severity without a score", func() {
	It("rates a malicious package critical without inventing a CVSS entry", func() {
		mal := model.Vulnerability{CVEID: "MAL-2026-1234"}.Normalized()

		Expect(mal.Kind).To(Equal(model.KindMalware))
		Expect(mal.TopSeverity()).To(Equal(model.SeverityCritical))
		// The rating is the finding's, not a score's. A fabricated CVSS entry
		// carried base_score 0, so anything reading the number saw the most
		// urgent finding in the system as the least severe.
		Expect(mal.Scores).To(BeEmpty())
	})

	It("leaves an ordinary finding unrated until a feed rates it", func() {
		cve := model.Vulnerability{CVEID: "CVE-2021-44228"}.Normalized()

		Expect(cve.TopSeverity()).To(Equal(model.SeverityUnknown))
	})

	It("still takes the worst rating a feed gave, when one did", func() {
		v := model.Vulnerability{
			CVEID: "CVE-2021-44228",
			Scores: []model.CVSS{
				{Version: "3.1", BaseScore: 5.3, Severity: model.SeverityMedium},
				{Version: "3.1", BaseScore: 10, Severity: model.SeverityCritical},
			},
		}.Normalized()

		Expect(v.TopSeverity()).To(Equal(model.SeverityCritical))
	})

	It("keeps malware critical even when a feed rates it lower", func() {
		mal := model.Vulnerability{
			CVEID:  "MAL-2026-1234",
			Scores: []model.CVSS{{Version: "3.1", BaseScore: 3.1, Severity: model.SeverityLow}},
		}.Normalized()

		// Installing a malicious package means the machine is compromised,
		// whatever a scoring rubric makes of the code.
		Expect(mal.TopSeverity()).To(Equal(model.SeverityCritical))
	})

	It("carries the rating through a merge", func() {
		mal := model.Vulnerability{CVEID: "MAL-2026-1234", Sources: []string{"package_feed"}}.Normalized()
		later := model.Vulnerability{CVEID: "MAL-2026-1234", Sources: []string{"gsd"}}.Normalized()

		Expect(mal.Merge(later).TopSeverity()).To(Equal(model.SeverityCritical))
	})
})
