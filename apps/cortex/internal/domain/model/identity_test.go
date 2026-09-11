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
