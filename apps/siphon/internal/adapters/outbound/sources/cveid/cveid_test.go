package cveid_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/cveid"
)

func TestCVEID(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Siphon CVE ID Extraction Suite")
}

var _ = Describe("CVE id extraction", func() {
	It("finds the first CVE id and upper-cases it", func() {
		Expect(cveid.First("fixed by cve-2021-44228 today")).To(Equal("CVE-2021-44228"))
	})

	It("returns empty when no CVE is present", func() {
		Expect(cveid.First("no identifier here")).To(BeEmpty())
	})

	It("finds all distinct ids in order, de-duplicated", func() {
		got := cveid.All("CVE-2021-44228;OSVDB-1;CVE-2021-45046;CVE-2021-44228")
		Expect(got).To(Equal([]string{"CVE-2021-44228", "CVE-2021-45046"}))
	})

	It("handles 7-digit CVE ids", func() {
		Expect(cveid.First("CVE-2024-1234567")).To(Equal("CVE-2024-1234567"))
	})

	It("extracts URLs from free text", func() {
		got := cveid.URLs(`see https://example.test/a and https://example.test/b.`)
		Expect(got).To(Equal([]string{"https://example.test/a", "https://example.test/b"}))
	})
})
