package manifest_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/repos/manifest"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// byName finds a parsed dependency, so specs do not depend on slice position.
func byName(deps []model.Dependency, name string) model.Dependency {
	GinkgoHelper()
	for _, d := range deps {
		if d.Package.Name == name {
			return d
		}
	}
	Fail("no dependency named " + name)
	return model.Dependency{}
}

var _ = Describe("go.mod parser", func() {
	const sample = `module github.com/gin-gonic/gin

go 1.23

toolchain go1.23.4

require (
	github.com/goccy/go-json v0.10.2
	golang.org/x/net v0.17.0
)

require (
	github.com/bytedance/sonic v1.10.2 // indirect
	golang.org/x/sys v0.13.0 // indirect
)

require github.com/stretchr/testify v1.8.4

replace golang.org/x/net => ./vendor/net

exclude github.com/old/module v1.0.0
`

	It("reads the module line as the library the repository publishes", func() {
		got, err := manifest.GoMod{}.Parse("go.mod", []byte(sample))
		Expect(err).ToNot(HaveOccurred())
		Expect(got.Publishes.Ecosystem).To(Equal(valueobject.EcosystemGo))
		Expect(got.Publishes.Name).To(Equal("github.com/gin-gonic/gin"))
	})

	It("reads every require across block and single forms", func() {
		got, err := manifest.GoMod{}.Parse("go.mod", []byte(sample))
		Expect(err).ToNot(HaveOccurred())
		Expect(got.Dependencies).To(HaveLen(5))
		Expect(byName(got.Dependencies, "github.com/stretchr/testify").Package.Version).To(Equal("v1.8.4"))
	})

	It("marks '// indirect' requirements as not direct", func() {
		got, err := manifest.GoMod{}.Parse("go.mod", []byte(sample))
		Expect(err).ToNot(HaveOccurred())
		Expect(byName(got.Dependencies, "golang.org/x/net").Direct).To(BeTrue())
		Expect(byName(got.Dependencies, "golang.org/x/sys").Direct).To(BeFalse())
		Expect(byName(got.Dependencies, "github.com/bytedance/sonic").Direct).To(BeFalse())
	})

	It("records where each requirement was declared", func() {
		got, err := manifest.GoMod{}.Parse("go.mod", []byte(sample))
		Expect(err).ToNot(HaveOccurred())
		Expect(byName(got.Dependencies, "golang.org/x/net").ManifestPath).To(Equal("go.mod"))
	})

	It("handles a module with no requirements", func() {
		got, err := manifest.GoMod{}.Parse("go.mod", []byte("module example.com/tiny\n\ngo 1.23\n"))
		Expect(err).ToNot(HaveOccurred())
		Expect(got.Publishes.Name).To(Equal("example.com/tiny"))
		Expect(got.Dependencies).To(BeEmpty())
	})

	It("survives a directive it does not understand", func() {
		// Lax parsing exists for exactly this: a newer toolchain writing a
		// directive we have never seen must not cost us the requires.
		got, err := manifest.GoMod{}.Parse("go.mod", []byte(
			"module example.com/x\n\ngodebug default=go1.21\n\nrequire golang.org/x/net v0.17.0\n"))
		Expect(err).ToNot(HaveOccurred())
		Expect(got.Dependencies).To(HaveLen(1))
	})

	It("reports a manifest it cannot parse at all", func() {
		_, err := manifest.GoMod{}.Parse("go.mod", []byte("require (\nunclosed\n"))
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("package.json parser", func() {
	const sample = `{
	  "name": "express",
	  "version": "4.18.2",
	  "dependencies": {"accepts": "~1.3.8", "body-parser": "1.20.1"},
	  "devDependencies": {"mocha": "10.2.0"}
	}`

	It("reads the name as the library the repository publishes", func() {
		got, err := manifest.PackageJSON{}.Parse("package.json", []byte(sample))
		Expect(err).ToNot(HaveOccurred())
		Expect(got.Publishes.Ecosystem).To(Equal(valueobject.EcosystemNPM))
		Expect(got.Publishes.Name).To(Equal("express"))
	})

	It("keeps the declared version constraint", func() {
		got, err := manifest.PackageJSON{}.Parse("package.json", []byte(sample))
		Expect(err).ToNot(HaveOccurred())
		Expect(byName(got.Dependencies, "accepts").Package.Version).To(Equal("~1.3.8"))
	})

	It("records devDependencies as an exposure, but not as direct", func() {
		// The repository really can be compromised through a build-time
		// package; whoever installs the published package cannot.
		got, err := manifest.PackageJSON{}.Parse("package.json", []byte(sample))
		Expect(err).ToNot(HaveOccurred())
		Expect(byName(got.Dependencies, "body-parser").Direct).To(BeTrue())
		Expect(byName(got.Dependencies, "mocha").Direct).To(BeFalse())
		Expect(byName(got.Dependencies, "mocha").ManifestPath).To(Equal("package.json (dev)"))
	})

	It("publishes nothing for a private package", func() {
		got, err := manifest.PackageJSON{}.Parse("package.json", []byte(`{"name":"internal-app","private":true,
		  "dependencies":{"react":"18.2.0"}}`))
		Expect(err).ToNot(HaveOccurred())
		Expect(got.Publishes.IsZero()).To(BeTrue(), "nothing can depend on a private package")
		Expect(got.Dependencies).To(HaveLen(1))
	})

	It("orders dependencies deterministically despite Go's map randomization", func() {
		raw := []byte(`{"name":"x","dependencies":{"zebra":"1","alpha":"1","middle":"1"}}`)
		first, err := manifest.PackageJSON{}.Parse("package.json", raw)
		Expect(err).ToNot(HaveOccurred())

		for i := 0; i < 20; i++ {
			again, err := manifest.PackageJSON{}.Parse("package.json", raw)
			Expect(err).ToNot(HaveOccurred())
			Expect(again.Dependencies).To(Equal(first.Dependencies))
		}
		Expect(first.Dependencies[0].Package.Name).To(Equal("alpha"))
	})

	It("handles a manifest with no dependencies", func() {
		got, err := manifest.PackageJSON{}.Parse("package.json", []byte(`{"name":"bare"}`))
		Expect(err).ToNot(HaveOccurred())
		Expect(got.Dependencies).To(BeEmpty())
	})

	It("reports malformed JSON", func() {
		_, err := manifest.PackageJSON{}.Parse("package.json", []byte(`{"name":`))
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("Parsers", func() {
	It("covers every registry advisories name, and Solidity through npm", func() {
		names := []string{}
		for _, p := range manifest.Parsers() {
			names = append(names, p.Name())
		}
		Expect(names).To(ContainElements("go.mod", "package.json", "requirements.txt", "pyproject.toml",
			"Pipfile", "Cargo.toml", "pom.xml", "build.gradle", "libs.versions.toml", "Gemfile.lock",
			"Gemfile", "composer.json", ".csproj", "Directory.Packages.props", "packages.config", "foundry.toml"))
	})
})
