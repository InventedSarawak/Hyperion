package valueobject_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

var _ = Describe("Identifier", func() {
	DescribeTable("recognises each scheme and puts it in canonical form",
		func(raw string, scheme valueobject.Scheme, canonical string) {
			id, ok := valueobject.ParseIdentifier(raw)
			Expect(ok).To(BeTrue())
			Expect(id.Scheme).To(Equal(scheme))
			Expect(id.Value).To(Equal(canonical))
		},
		Entry("CVE", "cve-2021-44228", valueobject.SchemeCVE, "CVE-2021-44228"),
		Entry("GHSA with a lower-case body", "GHSA-jfh8-c2jp-5v3q", valueobject.SchemeGHSA, "GHSA-jfh8-c2jp-5v3q"),
		Entry("GHSA typed in capitals", "ghsa-JFH8-C2JP-5V3Q", valueobject.SchemeGHSA, "GHSA-jfh8-c2jp-5v3q"),
		Entry("MAL", "mal-2026-2307", valueobject.SchemeMAL, "MAL-2026-2307"),
		Entry("PYSEC", "pysec-2021-19", valueobject.SchemeOther, "PYSEC-2021-19"),
		Entry("Go", "GO-2022-0001", valueobject.SchemeOther, "GO-2022-0001"),
		Entry("RustSec", "RUSTSEC-2021-0001", valueobject.SchemeOther, "RUSTSEC-2021-0001"),
		Entry("surrounding whitespace", "  CVE-2021-44228 ", valueobject.SchemeCVE, "CVE-2021-44228"),
	)

	It("rejects things that are not ids", func() {
		for _, raw := range []string{"", "   ", "log4j", "not an id", "-2021"} {
			_, ok := valueobject.ParseIdentifier(raw)
			Expect(ok).To(BeFalse(), "%q", raw)
		}
	})

	It("does not mistake a malformed GHSA for one", func() {
		// GHSA bodies use a restricted alphabet; "GHSA-only-1234" is not an
		// advisory id and must not be normalised as if it were.
		Expect(valueobject.SchemeOf("GHSA-only-1234")).To(Equal(valueobject.SchemeOther))
	})
})

var _ = Describe("Canonical", func() {
	It("prefers a CVE, then a GHSA, then a MAL, then anything else", func() {
		id, aliases := valueobject.Canonical("MAL-2026-1", "GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228", "PYSEC-2021-1")
		Expect(id).To(Equal("CVE-2021-44228"))
		Expect(aliases).To(Equal([]string{"GHSA-jfh8-c2jp-5v3q", "MAL-2026-1", "PYSEC-2021-1"}))

		id, _ = valueobject.Canonical("MAL-2026-2307", "GHSA-fw8c-xr5c-95f9")
		Expect(id).To(Equal("GHSA-fw8c-xr5c-95f9"), "reviewed malware: GitHub's id is shared by more feeds")

		id, aliases = valueobject.Canonical("MAL-2026-9999")
		Expect(id).To(Equal("MAL-2026-9999"))
		Expect(aliases).To(BeEmpty())
	})

	It("merges spellings of the same id and drops non-ids", func() {
		id, aliases := valueobject.Canonical("cve-2021-44228", "CVE-2021-44228", "garbage", "")
		Expect(id).To(Equal("CVE-2021-44228"))
		Expect(aliases).To(BeEmpty())
	})

	It("is order-independent, so every feed agrees on the canonical id", func() {
		a, aa := valueobject.Canonical("GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228", "MAL-2026-1")
		b, bb := valueobject.Canonical("MAL-2026-1", "CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q")
		Expect(a).To(Equal(b))
		Expect(aa).To(Equal(bb))
	})

	It("breaks a tie within one scheme deterministically", func() {
		a, _ := valueobject.Canonical("CVE-2021-45046", "CVE-2021-44228")
		b, _ := valueobject.Canonical("CVE-2021-44228", "CVE-2021-45046")
		Expect(a).To(Equal(b))
	})

	It("returns nothing when there is no id at all", func() {
		id, aliases := valueobject.Canonical("", "nope")
		Expect(id).To(BeEmpty())
		Expect(aliases).To(BeNil())
	})
})
