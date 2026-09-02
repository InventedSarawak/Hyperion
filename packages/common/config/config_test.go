package config_test

import (
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/packages/common/config"
)

func TestConfig(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Common Config Suite")
}

var _ = Describe("namespaced config loader", func() {
	It("maps SERVICE.VAR to the SERVICE_VAR environment variable", func() {
		l := config.For("siphon")
		Expect(l.Key("NVD_API_KEY")).To(Equal("SIPHON_NVD_API_KEY"))
		Expect(l.Key("nvd_api_key")).To(Equal("SIPHON_NVD_API_KEY"))
	})

	It("reads typed values from the environment", func() {
		GinkgoT().Setenv("TESTSVC_NAME", "hyperion")
		GinkgoT().Setenv("TESTSVC_COUNT", "42")
		GinkgoT().Setenv("TESTSVC_ENABLED", "true")
		GinkgoT().Setenv("TESTSVC_WAIT", "90s")
		GinkgoT().Setenv("TESTSVC_ITEMS", "a, b ,c")

		l := config.For("testsvc")
		Expect(l.String("NAME", "fallback")).To(Equal("hyperion"))
		Expect(l.Int("COUNT", 1)).To(Equal(42))
		Expect(l.Bool("ENABLED", false)).To(BeTrue())
		Expect(l.Duration("WAIT", time.Second)).To(Equal(90 * time.Second))
		Expect(l.List("ITEMS", nil)).To(Equal([]string{"a", "b", "c"}))
	})

	It("falls back to defaults when unset or unparsable", func() {
		GinkgoT().Setenv("TESTSVC_COUNT2", "not-a-number")

		l := config.For("testsvc")
		Expect(l.String("MISSING", "default")).To(Equal("default"))
		Expect(l.Int("COUNT2", 7)).To(Equal(7))
		Expect(l.Bool("MISSING", true)).To(BeTrue())
		Expect(l.Duration("MISSING", time.Minute)).To(Equal(time.Minute))
		Expect(l.List("MISSING", []string{"x"})).To(Equal([]string{"x"}))
	})

	It("reports whether a value was supplied", func() {
		GinkgoT().Setenv("TESTSVC_PRESENT", "yes")
		l := config.For("testsvc")

		Expect(l.Has("PRESENT")).To(BeTrue())
		Expect(l.Has("ABSENT")).To(BeFalse())
	})

	It("masks secrets in diagnostics but returns the real value", func() {
		GinkgoT().Setenv("TESTSVC_TOKEN", "abcdefghijklmnop")
		l := config.For("testsvc")

		Expect(l.Secret("TOKEN")).To(Equal("abcdefghijklmnop"))

		var entry config.Entry
		for _, e := range l.Describe() {
			if e.Key == "TESTSVC_TOKEN" {
				entry = e
			}
		}
		Expect(entry.Secret).To(BeTrue())
		Expect(entry.Value).To(Equal("abcd...mnop"))
		Expect(entry.Value).ToNot(ContainSubstring("efghijkl"))
	})

	It("marks an unset secret as (unset)", func() {
		l := config.For("testsvc")
		Expect(l.Secret("NO_SUCH_TOKEN")).To(BeEmpty())
		Expect(l.Describe()[0].Value).To(Equal("(unset)"))
	})
})
