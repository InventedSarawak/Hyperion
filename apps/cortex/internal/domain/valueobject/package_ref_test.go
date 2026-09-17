package valueobject_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

var _ = Describe("Ecosystem", func() {
	It("normalizes the spellings upstream feeds actually use", func() {
		// GitHub says "pip" and "rust"; OSV says "PyPI" and "crates.io".
		// Both must land on the same node or the graph silently forks.
		Expect(valueobject.ParseEcosystem("pip")).To(Equal(valueobject.EcosystemPyPI))
		Expect(valueobject.ParseEcosystem("PyPI")).To(Equal(valueobject.EcosystemPyPI))
		Expect(valueobject.ParseEcosystem("rust")).To(Equal(valueobject.EcosystemCargo))
		Expect(valueobject.ParseEcosystem("crates.io")).To(Equal(valueobject.EcosystemCargo))
		Expect(valueobject.ParseEcosystem("composer")).To(Equal(valueobject.EcosystemPackagist))
		Expect(valueobject.ParseEcosystem("  Go  ")).To(Equal(valueobject.EcosystemGo))
	})

	It("returns unknown for a registry it does not model, rather than failing", func() {
		Expect(valueobject.ParseEcosystem("conda")).To(Equal(valueobject.EcosystemUnknown))
		Expect(valueobject.EcosystemUnknown.IsValid()).To(BeFalse())
	})

	It("recognizes every canonical ecosystem", func() {
		for _, e := range valueobject.AllEcosystems() {
			Expect(e.IsValid()).To(BeTrue(), "expected %s to be valid", e)
			Expect(valueobject.ParseEcosystem(e.String())).To(Equal(e))
		}
	})
})

var _ = Describe("PackageRef", func() {
	It("requires a name", func() {
		Expect(valueobject.PackageRef{Ecosystem: valueobject.EcosystemNPM}.Validate()).
			To(MatchError(valueobject.ErrMissingPackageName))
		Expect(valueobject.NewPackageRef("npm", "lodash", "4.17.20").Validate()).To(Succeed())
	})

	It("keys on ecosystem and name only, so versions converge on one library", func() {
		a := valueobject.NewPackageRef("npm", "lodash", "4.17.20")
		b := valueobject.NewPackageRef("npm", "lodash", "4.17.21")
		Expect(a.Key()).To(Equal(b.Key()))
		Expect(a.Key()).To(Equal("npm:lodash"))
	})

	It("keeps same-named packages in different registries apart", func() {
		Expect(valueobject.NewPackageRef("pypi", "requests", "").Key()).
			ToNot(Equal(valueobject.NewPackageRef("rubygems", "requests", "").Key()))
	})

	It("renders the version for display but not for identity", func() {
		Expect(valueobject.NewPackageRef("go", "github.com/gin-gonic/gin", "v1.9.1").String()).
			To(Equal("go:github.com/gin-gonic/gin@v1.9.1"))
		Expect(valueobject.NewPackageRef("go", "github.com/gin-gonic/gin", "").String()).
			To(Equal("go:github.com/gin-gonic/gin"))
	})
})

var _ = Describe("package name normalization", func() {
	DescribeTable("folds the spellings a registry considers equal",
		func(ecosystem, written, other string) {
			one := valueobject.NewPackageRef(ecosystem, written, "1.0.0")
			two := valueobject.NewPackageRef(ecosystem, other, "2.0.0")

			// The join key is what decides whether a manifest reaches the
			// advisories filed against the same package.
			Expect(one.Key()).To(Equal(two.Key()))
			// And the original spelling survives for display.
			Expect(one.Name).To(Equal(written))
		},
		Entry("NuGet ids are case-insensitive",
			"nuget", "Newtonsoft.Json", "newtonsoft.json"),
		Entry("Packagist names are case-insensitive",
			"packagist", "Monolog/Monolog", "monolog/monolog"),
		Entry("PyPI folds case (PEP 503)",
			"pypi", "Django", "django"),
		Entry("PyPI folds separators (PEP 503)",
			"pypi", "zope.interface", "zope-interface"),
		Entry("PyPI folds underscores too",
			"pypi", "typing_extensions", "typing-extensions"),
	)

	DescribeTable("leaves alone the registries where spelling is meaning",
		func(ecosystem, written, other string) {
			one := valueobject.NewPackageRef(ecosystem, written, "")
			two := valueobject.NewPackageRef(ecosystem, other, "")

			Expect(one.Key()).NotTo(Equal(two.Key()))
		},
		// Gem names are case-sensitive by specification: folding them would
		// be inventing a fact rather than applying one.
		Entry("RubyGems", "rubygems", "Rails", "rails"),
		Entry("npm scopes are case-sensitive", "npm", "React", "react"),
		Entry("Go module paths are case-sensitive", "go", "github.com/A/b", "github.com/a/b"),
	)

	It("keeps the ecosystem in the key, so one name in two registries stays two libraries", func() {
		Expect(valueobject.NewPackageRef("nuget", "serilog", "").Key()).
			NotTo(Equal(valueobject.NewPackageRef("npm", "serilog", "").Key()))
	})
})
