package manifest_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/repos/manifest"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
)

// A lockfile is a graph, not a list: it records which package pulled in which.
// Keeping that is what lets a blast radius answer "how does this reach me?"
// with a path rather than a list of everything installed.
func edgeNames(s model.RepositorySnapshot) []string {
	out := make([]string, 0, len(s.Dependencies))
	for _, e := range s.DependencyEdges() {
		out = append(out, e.From.Name+" -> "+e.To.Name)
	}
	return out
}

var _ = Describe("Dependency edges from lockfiles", func() {
	It("reads them from yarn.lock v1", func() {
		snapshot, err := manifest.YarnLock{}.Parse("yarn.lock", []byte(`# yarn lockfile v1

"@babel/core@^7.0.0", "@babel/core@^7.20.0":
  version "7.23.0"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.23.0.tgz"
  dependencies:
    "@babel/helpers" "^7.23.0"
    semver "^6.3.1"

"@babel/helpers@^7.23.0":
  version "7.23.1"
  dependencies:
    semver "^6.3.1"

semver@^6.3.1:
  version "6.3.1"
`))
		Expect(err).ToNot(HaveOccurred())
		Expect(edgeNames(snapshot)).To(Equal([]string{
			"@babel/core -> @babel/helpers",
			"@babel/core -> semver",
			"@babel/helpers -> semver",
		}))
		// Two ranges in one header are one package, not two.
		Expect(byName(snapshot.Dependencies, "@babel/core").DependsOn).To(HaveLen(2))
	})

	It("reads them from yarn.lock Berry, without peer dependencies", func() {
		// A peer is installed by whoever consumes the package, not by the
		// package, so an edge from here would say what the lockfile does not.
		snapshot, err := manifest.YarnLock{}.Parse("yarn.lock", []byte(`__metadata:
  version: 8

"lodash@npm:^4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  dependencies:
    tiny-dep: "npm:^1.0.0"
  peerDependencies:
    react: "*"
  checksum: abc

"tiny-dep@npm:^1.0.0":
  version: 1.0.2

"react@npm:18.0.0":
  version: 18.0.0
`))
		Expect(err).ToNot(HaveOccurred())
		Expect(edgeNames(snapshot)).To(Equal([]string{"lodash -> tiny-dep"}))
	})

	It("reads them from package-lock.json", func() {
		snapshot, err := manifest.PackageLock{}.Parse("package-lock.json", []byte(`{
 "lockfileVersion": 3,
 "packages": {
   "": {"dependencies": {"express": "^4.0.0"}},
   "node_modules/express": {"version": "4.18.2", "dependencies": {"body-parser": "1.20.1", "cookie": "0.5.0"}},
   "node_modules/body-parser": {"version": "1.20.1", "dependencies": {"bytes": "3.1.2"}},
   "node_modules/cookie": {"version": "0.5.0"},
   "node_modules/bytes": {"version": "3.1.2"}
 }}`))
		Expect(err).ToNot(HaveOccurred())
		Expect(edgeNames(snapshot)).To(Equal([]string{
			"body-parser -> bytes",
			"express -> body-parser",
			"express -> cookie",
		}))
	})

	It("reads them from pnpm-lock.yaml v9, where they live under snapshots", func() {
		snapshot, err := manifest.PnpmLock{}.Parse("pnpm-lock.yaml", []byte(`lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      vite: {specifier: ^5.0.0, version: 5.0.0}
packages:
  vite@5.0.0:
    resolution: {integrity: sha1-x}
  esbuild@0.19.0:
    resolution: {integrity: sha1-y}
snapshots:
  vite@5.0.0:
    dependencies:
      esbuild: 0.19.0
  esbuild@0.19.0: {}
`))
		Expect(err).ToNot(HaveOccurred())
		Expect(edgeNames(snapshot)).To(Equal([]string{"vite -> esbuild"}))
	})

	It("reads them from Cargo.lock, whose requirements carry a version and source", func() {
		snapshot, err := manifest.CargoLock{}.Parse("Cargo.lock", []byte(`
[[package]]
name = "serde"
version = "1.0.190"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["serde_derive"]

[[package]]
name = "serde_derive"
version = "1.0.190"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["syn 2.0.38 (registry+https://github.com/rust-lang/crates.io-index)"]

[[package]]
name = "syn"
version = "2.0.38"
source = "registry+https://github.com/rust-lang/crates.io-index"
`))
		Expect(err).ToNot(HaveOccurred())
		Expect(edgeNames(snapshot)).To(Equal([]string{
			"serde -> serde_derive",
			"serde_derive -> syn",
		}))
	})

	It("reads them from packages.lock.json", func() {
		snapshot, err := manifest.PackagesLock{}.Parse("packages.lock.json", []byte(`{"version":1,"dependencies":{"net8.0":{
  "Serilog":{"type":"Direct","requested":"[3.1.1, )","resolved":"3.1.1"},
  "Serilog.Sinks.Console":{"type":"Transitive","resolved":"5.0.0","dependencies":{"Serilog":"3.1.1"}}
}}}`))
		Expect(err).ToNot(HaveOccurred())
		Expect(edgeNames(snapshot)).To(Equal([]string{"Serilog.Sinks.Console -> Serilog"}))
	})

	It("reads them from composer.lock, dropping platform constraints", func() {
		// "php" and "ext-*" are requirements, but not of packages.
		snapshot, err := manifest.ComposerLock{}.Parse("composer.lock", []byte(`{"packages":[
 {"name":"monolog/monolog","version":"3.5.0","require":{"php":">=8.1","ext-json":"*","psr/log":"^3"}},
 {"name":"psr/log","version":"3.0.0","require":{"php":">=8.0"}}]}`))
		Expect(err).ToNot(HaveOccurred())
		Expect(edgeNames(snapshot)).To(Equal([]string{"monolog/monolog -> psr/log"}))
	})

	It("reports no edges for a manifest, which states none", func() {
		// package.json names what the project asked for and nothing about
		// what those ask for in turn. Empty means "not stated".
		snapshot, err := manifest.PackageJSON{}.Parse("package.json",
			[]byte(`{"name":"app","dependencies":{"express":"^4.0.0"}}`))
		Expect(err).ToNot(HaveOccurred())
		Expect(snapshot.Dependencies).ToNot(BeEmpty())
		Expect(snapshot.DependencyEdges()).To(BeEmpty())
	})
})
