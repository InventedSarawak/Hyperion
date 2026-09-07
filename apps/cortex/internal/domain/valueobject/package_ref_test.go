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
