package manifest_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/repos/manifest"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// named finds one dependency by package name, or fails.
func named(deps []model.Dependency, name string) model.Dependency {
	GinkgoHelper()
	for _, d := range deps {
		if d.Package.Name == name {
			return d
		}
	}
	Fail(fmt.Sprintf("no dependency named %s in %v", name, packageNames(deps)))
	return model.Dependency{}
}

func packageNames(deps []model.Dependency) []string {
	out := []string{}
	for _, d := range deps {
		out = append(out, d.Package.Name)
	}
	return out
}

func parse(p manifest.Parser, filePath, content string) model.RepositorySnapshot {
	GinkgoHelper()
	got, err := p.Parse(filePath, []byte(content))
	Expect(err).ToNot(HaveOccurred())
	return got
}

var _ = Describe("Discover", func() {
	It("picks dependency files anywhere, shallowest first, skipping installed and generated code", func() {
		found, dropped := manifest.Discover([]string{
			"README.md", "package.json", "apps/api/go.mod", "apps/web/package.json",
			"node_modules/left-pad/package.json", "apps/web/node_modules/react/package.json",
			"backend/requirements.txt", "examples/demo/package.json", "contracts/foundry.toml",
			"Gemfile", "Gemfile.lock", "dist/package.json", "src/App.csproj", "docs/requirements.txt",
		}, manifest.Parsers())

		paths := []string{}
		for _, f := range found {
			paths = append(paths, f.Path)
		}
		Expect(paths).To(Equal([]string{
			"Gemfile.lock", "package.json",
			"backend/requirements.txt", "contracts/foundry.toml", "docs/requirements.txt", "src/App.csproj",
			"apps/api/go.mod", "apps/web/package.json",
		}), "Gemfile gives way to its lock; node_modules, dist and examples are not the repository's own")
		Expect(dropped).To(BeZero())
	})

	It("reads at most MaxManifests files, and says how many it left out", func() {
		var paths []string
		for i := 0; i < manifest.MaxManifests+10; i++ {
			paths = append(paths, fmt.Sprintf("pkg%03d/package.json", i))
		}
		found, dropped := manifest.Discover(paths, manifest.Parsers())
		Expect(found).To(HaveLen(manifest.MaxManifests))
		Expect(dropped).To(Equal(10))
	})
})

var _ = Describe("Go modules in a monorepo", func() {
	It("leaves out the repository's own modules, wired in by replace", func() {
		got := parse(manifest.GoMod{}, "apps/api/go.mod", `module github.com/acme/mono/apps/api

go 1.22

require (
	github.com/acme/mono/packages/contracts v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.60.0
)

replace github.com/acme/mono/packages/contracts => ../../packages/contracts
`)
		Expect(packageNames(got.Dependencies)).To(Equal([]string{"google.golang.org/grpc"}))
		Expect(got.Dependencies[0].ManifestPath).To(Equal("apps/api/go.mod"))
	})
})

var _ = Describe("Python", func() {
	It("reads a requirements file: pins, extras, markers, and nothing that is not a package", func() {
		got := parse(manifest.Requirements{}, "backend/requirements.txt", `# API
fastapi==0.109.2
uvicorn[standard]==0.27.1
Flask>=3.0,<4 ; python_version >= "3.8"
python_dateutil==2.9.0  # dates
gunicorn
requests==2.31.0 \
    --hash=sha256:abc
-r base.txt
-e git+https://github.com/acme/tool.git#egg=tool
https://example.test/pkg.tar.gz
`)
		Expect(packageNames(got.Dependencies)).To(Equal([]string{
			"fastapi", "uvicorn", "flask", "python-dateutil", "gunicorn", "requests"}))
		fastapi := named(got.Dependencies, "fastapi")
		Expect(fastapi.Package.Ecosystem).To(Equal(valueobject.EcosystemPyPI))
		Expect(fastapi.Package.Version).To(Equal("==0.109.2"))
		Expect(fastapi.Direct).To(BeTrue())
		Expect(fastapi.ManifestPath).To(Equal("backend/requirements.txt"))
		Expect(named(got.Dependencies, "uvicorn").Package.Version).To(Equal("==0.27.1"), "extras are not part of the version")
		Expect(named(got.Dependencies, "flask").Package.Version).To(Equal(">=3.0,<4"), "the environment marker is dropped")
		Expect(named(got.Dependencies, "gunicorn").Package.Version).To(BeEmpty(), "unpinned")
		Expect(named(got.Dependencies, "requests").Package.Version).To(Equal("==2.31.0"), "the hash option is dropped")
	})

	It("records a development requirements file as indirect", func() {
		got := parse(manifest.Requirements{}, "requirements-dev.txt", "pytest==8.0.0\n")
		Expect(got.Dependencies[0].Direct).To(BeFalse())
		Expect(got.Dependencies[0].ManifestPath).To(Equal("requirements-dev.txt (dev)"))
	})

	It("recognises the ways projects name requirements files", func() {
		for _, p := range []string{"requirements.txt", "requirements-dev.txt", "requirements/base.txt", "docs-requirements.txt"} {
			Expect(manifest.Requirements{}.Matches(p)).To(BeTrue(), p)
		}
		Expect(manifest.Requirements{}.Matches("notes.txt")).To(BeFalse())
	})

	It("reads pyproject.toml: PEP 621, dependency groups and Poetry", func() {
		got := parse(manifest.Pyproject{}, "pyproject.toml", `
[project]
name = "My_Service"
dependencies = ["httpx>=0.27", "pydantic[email]==2.6.1"]

[project.optional-dependencies]
test = ["pytest==8.0.0"]

[dependency-groups]
lint = ["ruff==0.3.0", {include-group = "test"}]

[tool.poetry.dependencies]
python = "^3.11"
Django = "^5.0"
celery = { version = "5.3.6", extras = ["redis"] }
mylib = { path = "../mylib" }

[tool.poetry.group.dev.dependencies]
black = "24.2.0"
`)
		Expect(got.Publishes.Name).To(Equal("my-service"))
		Expect(named(got.Dependencies, "httpx").Package.Version).To(Equal(">=0.27"))
		Expect(named(got.Dependencies, "pydantic").Package.Version).To(Equal("==2.6.1"))
		Expect(named(got.Dependencies, "pytest").Direct).To(BeFalse())
		Expect(named(got.Dependencies, "ruff").Direct).To(BeFalse())
		Expect(named(got.Dependencies, "django").Package.Version).To(Equal("^5.0"))
		Expect(named(got.Dependencies, "celery").Package.Version).To(Equal("5.3.6"))
		Expect(named(got.Dependencies, "black").Direct).To(BeFalse())
		Expect(packageNames(got.Dependencies)).ToNot(ContainElements("python", "mylib"),
			"the interpreter and a local path are not packages")
	})

	It("reads a Pipfile", func() {
		got := parse(manifest.Pipfile{}, "Pipfile", `
[packages]
requests = "*"
django = {version = "==5.0.2"}

[dev-packages]
pytest = "==8.0.0"
`)
		Expect(named(got.Dependencies, "requests").Package.Version).To(BeEmpty())
		Expect(named(got.Dependencies, "django").Package.Version).To(Equal("==5.0.2"))
		Expect(named(got.Dependencies, "pytest").Direct).To(BeFalse())
	})
})

var _ = Describe("Rust", func() {
	It("reads Cargo.toml: renames, workspace inheritance, targets, and no local crates", func() {
		got := parse(manifest.Cargo{}, "crates/core/Cargo.toml", `
[package]
name = "ledger-core"

[dependencies]
serde = "1.0"
tokio = { version = "1.36", features = ["full"] }
rng = { package = "rand", version = "0.8" }
local-crate = { path = "../local" }
shared = { workspace = true }

[dev-dependencies]
criterion = "0.5"

[target.'cfg(unix)'.dependencies]
nix = "0.27"

[workspace.dependencies]
shared = "2.1"
`)
		Expect(got.Publishes.Name).To(Equal("ledger-core"))
		Expect(got.Publishes.Ecosystem).To(Equal(valueobject.EcosystemCargo))
		Expect(named(got.Dependencies, "serde").Package.Version).To(Equal("1.0"))
		Expect(named(got.Dependencies, "tokio").Package.Version).To(Equal("1.36"))
		Expect(named(got.Dependencies, "rand").Package.Version).To(Equal("0.8"), "recorded under the crate's real name")
		Expect(named(got.Dependencies, "shared").Package.Version).To(Equal("2.1"))
		Expect(named(got.Dependencies, "criterion").Direct).To(BeFalse())
		Expect(named(got.Dependencies, "nix").Direct).To(BeTrue())
		Expect(packageNames(got.Dependencies)).ToNot(ContainElement("local-crate"))
	})
})

var _ = Describe("Java", func() {
	It("reads pom.xml, resolving properties and managed versions", func() {
		got := parse(manifest.Pom{}, "api/pom.xml", `<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.acme</groupId><artifactId>api</artifactId><version>1.0.0</version>
  <properties><jackson.version>2.14.1</jackson.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.9</version></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>${jackson.version}</version></dependency>
    <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId></dependency>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version><scope>test</scope></dependency>
    <dependency><groupId>org.acme</groupId><artifactId>from-parent</artifactId><version>${parent.only}</version></dependency>
  </dependencies>
</project>`)
		Expect(got.Publishes.Name).To(Equal("com.acme:api"))
		databind := named(got.Dependencies, "com.fasterxml.jackson.core:jackson-databind")
		Expect(databind.Package.Ecosystem).To(Equal(valueobject.EcosystemMaven))
		Expect(databind.Package.Version).To(Equal("2.14.1"))
		Expect(named(got.Dependencies, "org.slf4j:slf4j-api").Package.Version).To(Equal("2.0.9"))
		Expect(named(got.Dependencies, "junit:junit").Direct).To(BeFalse())
		Expect(named(got.Dependencies, "org.acme:from-parent").Package.Version).To(BeEmpty(),
			"a property from a parent pom is unknown, not guessed")
	})

	It("reads an Android Gradle build script", func() {
		got := parse(manifest.Gradle{}, "reprting_app/app/build.gradle", `plugins {
    id 'com.android.application'
}

android {
    namespace 'com.example.reportaccident'
    defaultConfig {
        applicationId "com.example.reportaccident"
        testInstrumentationRunner "androidx.test.runner.AndroidJUnitRunner"
    }
}

dependencies {
    implementation 'androidx.appcompat:appcompat:1.6.1'
    implementation 'com.google.android.material:material:1.12.0'
    testImplementation 'junit:junit:4.13.2'
    androidTestImplementation 'androidx.test.espresso:espresso-core:3.5.1'
}`)
		Expect(packageNames(got.Dependencies)).To(ConsistOf("androidx.appcompat:appcompat",
			"com.google.android.material:material", "junit:junit", "androidx.test.espresso:espresso-core"))
		appcompat := named(got.Dependencies, "androidx.appcompat:appcompat")
		Expect(appcompat.Package.Version).To(Equal("1.6.1"))
		Expect(appcompat.Direct).To(BeTrue())
		Expect(named(got.Dependencies, "junit:junit").Direct).To(BeFalse())
		Expect(named(got.Dependencies, "androidx.test.espresso:espresso-core").Direct).To(BeFalse())
	})

	It("reads the Kotlin DSL, platforms and map notation, leaving variables unknown", func() {
		got := parse(manifest.Gradle{}, "build.gradle.kts", `dependencies {
    implementation("io.ktor:ktor-server-core:2.3.7")
    implementation(platform("org.jetbrains.kotlin:kotlin-bom:1.9.22"))
    api(group = "com.google.guava", name = "guava", version = "33.0.0-jre")
    implementation("com.squareup.okhttp3:okhttp:$okhttpVersion")
    testImplementation("io.kotest:kotest-runner-junit5:5.8.0")
}`)
		Expect(named(got.Dependencies, "io.ktor:ktor-server-core").Package.Version).To(Equal("2.3.7"))
		Expect(named(got.Dependencies, "org.jetbrains.kotlin:kotlin-bom").Package.Version).To(Equal("1.9.22"))
		Expect(named(got.Dependencies, "com.google.guava:guava").Package.Version).To(Equal("33.0.0-jre"))
		Expect(named(got.Dependencies, "com.squareup.okhttp3:okhttp").Package.Version).To(BeEmpty())
		Expect(named(got.Dependencies, "io.kotest:kotest-runner-junit5").Direct).To(BeFalse())
	})

	It("reads a Gradle version catalog", func() {
		got := parse(manifest.VersionCatalog{}, "gradle/libs.versions.toml", `
[versions]
agp = "8.2.2"
coreKtx = "1.12.0"

[libraries]
androidx-core-ktx = { group = "androidx.core", name = "core-ktx", version.ref = "coreKtx" }
junit = "junit:junit:4.13.2"
material = { module = "com.google.android.material:material", version = "1.11.0" }

[plugins]
android-application = { id = "com.android.application", version.ref = "agp" }
`)
		Expect(packageNames(got.Dependencies)).To(ConsistOf("androidx.core:core-ktx", "junit:junit",
			"com.google.android.material:material"), "plugins are not dependencies")
		Expect(named(got.Dependencies, "androidx.core:core-ktx").Package.Version).To(Equal("1.12.0"))
		Expect(named(got.Dependencies, "junit:junit").Package.Version).To(Equal("4.13.2"))
	})
})

var _ = Describe("Ruby", func() {
	It("reads a Gemfile.lock at exact versions, direct where the Gemfile asked", func() {
		got := parse(manifest.GemfileLock{}, "Gemfile.lock", `GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.0.4)
      rack (~> 2.0)
    nokogiri (1.13.10-x86_64-linux)
      racc (~> 1.4)
    rack (2.2.6)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  actionpack (~> 7.0.4)
  nokogiri

BUNDLED WITH
   2.4.10
`)
		Expect(packageNames(got.Dependencies)).To(ConsistOf("actionpack", "nokogiri", "rack"))
		Expect(named(got.Dependencies, "actionpack").Package.Version).To(Equal("7.0.4"))
		Expect(named(got.Dependencies, "nokogiri").Package.Version).To(Equal("1.13.10"), "the platform is not the version")
		Expect(named(got.Dependencies, "rack").Direct).To(BeFalse(), "it came along with actionpack")
		Expect(named(got.Dependencies, "actionpack").Package.Ecosystem).To(Equal(valueobject.EcosystemRubyGems))
	})

	It("reads a Gemfile's constraints and development groups", func() {
		got := parse(manifest.Gemfile{}, "Gemfile", `source "https://rubygems.org"
gem "rails", "~> 7.0", ">= 7.0.4"
gem 'pg'
group :development, :test do
  gem "rspec-rails", "~> 6.0"
end
gem "puma", "~> 6.4", require: false
`)
		Expect(named(got.Dependencies, "rails").Package.Version).To(Equal("~> 7.0, >= 7.0.4"))
		Expect(named(got.Dependencies, "pg").Package.Version).To(BeEmpty())
		Expect(named(got.Dependencies, "rspec-rails").Direct).To(BeFalse())
		Expect(named(got.Dependencies, "puma").Package.Version).To(Equal("~> 6.4"))
		Expect(named(got.Dependencies, "puma").Direct).To(BeTrue(), "the group has closed")
	})
})

var _ = Describe("PHP", func() {
	It("reads composer.json, skipping platform requirements", func() {
		got := parse(manifest.Composer{}, "composer.json", `{"name":"Acme/Shop",
		  "require":{"php":">=8.1","ext-json":"*","laravel/framework":"^10.0","Guzzlehttp/Guzzle":"~7.8"},
		  "require-dev":{"phpunit/phpunit":"^10.5"}}`)
		Expect(got.Publishes.Name).To(Equal("acme/shop"))
		Expect(packageNames(got.Dependencies)).To(ConsistOf("laravel/framework", "guzzlehttp/guzzle", "phpunit/phpunit"))
		Expect(named(got.Dependencies, "guzzlehttp/guzzle").Package.Version).To(Equal("~7.8"))
		Expect(named(got.Dependencies, "phpunit/phpunit").Direct).To(BeFalse())
	})
})

var _ = Describe(".NET", func() {
	It("reads PackageReference items, build-only analyzers as indirect", func() {
		got := parse(manifest.MSBuild{}, "src/Api/Api.csproj", `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
    <PackageReference Include="Serilog"><Version>3.1.1</Version></PackageReference>
    <PackageReference Include="StyleCop.Analyzers" Version="1.1.118" PrivateAssets="all" />
    <PackageReference Include="Azure.Identity" Version="$(AzureVersion)" />
  </ItemGroup>
</Project>`)
		Expect(named(got.Dependencies, "Newtonsoft.Json").Package.Version).To(Equal("13.0.1"))
		Expect(named(got.Dependencies, "Newtonsoft.Json").Package.Ecosystem).To(Equal(valueobject.EcosystemNuGet))
		Expect(named(got.Dependencies, "Serilog").Package.Version).To(Equal("3.1.1"))
		Expect(named(got.Dependencies, "StyleCop.Analyzers").Direct).To(BeFalse())
		Expect(named(got.Dependencies, "Azure.Identity").Package.Version).To(BeEmpty())
	})

	It("reads central package versions and packages.config", func() {
		central := parse(manifest.CentralPackages{}, "Directory.Packages.props", `<Project>
  <ItemGroup><PackageVersion Include="Polly" Version="8.2.1" /></ItemGroup>
</Project>`)
		Expect(named(central.Dependencies, "Polly").Package.Version).To(Equal("8.2.1"))

		legacy := parse(manifest.PackagesConfig{}, "packages.config", `<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="jQuery" version="3.4.1" targetFramework="net48" />
  <package id="Microsoft.CodeDom.Providers" version="2.0.1" developmentDependency="true" />
</packages>`)
		Expect(named(legacy.Dependencies, "jQuery").Package.Version).To(Equal("3.4.1"))
		Expect(named(legacy.Dependencies, "Microsoft.CodeDom.Providers").Direct).To(BeFalse())
	})
})

var _ = Describe("Solidity", func() {
	It("reads Soldeer dependencies as the npm packages advisories name", func() {
		got := parse(manifest.Foundry{}, "contracts/foundry.toml", `
[profile.default]
src = "src"

[dependencies]
"@openzeppelin-contracts" = "5.0.2"
forge-std = "1.8.1"
`)
		Expect(got.Dependencies).To(HaveLen(1), "forge-std has no advisories under any name")
		Expect(got.Dependencies[0].Package.Ecosystem).To(Equal(valueobject.EcosystemNPM))
		Expect(got.Dependencies[0].Package.Name).To(Equal("@openzeppelin/contracts"))
		Expect(got.Dependencies[0].Package.Version).To(Equal("5.0.2"))
		Expect(got.Dependencies[0].ManifestPath).To(Equal("contracts/foundry.toml (soldeer)"))
	})

	It("reads a foundry.toml that only configures the build", func() {
		got := parse(manifest.Foundry{}, "contracts/foundry.toml", `[profile.default]
src = "src"
libs = ["lib"]
remappings = ["@openzeppelin/=lib/openzeppelin-contracts/"]
ignored_error_codes = [5574, 2018]
`)
		Expect(got.Dependencies).To(BeEmpty())
	})

	It("reads .gitmodules and knows where each vendored library states its version", func() {
		subs := manifest.ParseGitmodules([]byte(`[submodule "contracts/lib/forge-std"]
	path = contracts/lib/forge-std
	url = https://github.com/foundry-rs/forge-std
[submodule "contracts/lib/openzeppelin-contracts"]
	path = contracts/lib/openzeppelin-contracts
	url = https://github.com/OpenZeppelin/openzeppelin-contracts
`))
		Expect(subs).To(Equal([]manifest.Submodule{
			{Path: "contracts/lib/forge-std", URL: "https://github.com/foundry-rs/forge-std"},
			{Path: "contracts/lib/openzeppelin-contracts", URL: "https://github.com/OpenZeppelin/openzeppelin-contracts"},
		}))

		oz, ok := manifest.SourceOf(subs[1].URL)
		Expect(ok).To(BeTrue())
		Expect(oz).To(Equal(manifest.SubmoduleSource{Owner: "OpenZeppelin", Repo: "openzeppelin-contracts",
			VersionFile: "contracts/package.json", Package: "@openzeppelin/contracts"}))

		solmate, ok := manifest.SourceOf("git@github.com:transmissions11/solmate.git")
		Expect(ok).To(BeTrue())
		Expect(solmate.Repo).To(Equal("solmate"))
		Expect(solmate.VersionFile).To(Equal("package.json"))

		_, ok = manifest.SourceOf("https://gitlab.com/acme/lib")
		Expect(ok).To(BeFalse(), "only GitHub can be read")
	})
})

var _ = Describe("Lockfiles", func() {
	It("reads package-lock.json: installed versions, direct from the root entry", func() {
		got := parse(manifest.PackageLock{}, "frontend/package-lock.json", `{
		  "name": "frontend", "lockfileVersion": 3,
		  "packages": {
		    "": {"version": "1.0.0", "dependencies": {"axios": "^1.6.5", "react": "^18.2.0"}},
		    "node_modules/axios": {"version": "1.13.6"},
		    "node_modules/react": {"version": "18.3.1"},
		    "node_modules/@floating-ui/core": {"version": "1.7.5"},
		    "node_modules/typescript": {"version": "5.4.2", "dev": true},
		    "node_modules/foo/node_modules/bar": {"version": "2.0.0"},
		    "packages/ui": {"link": true, "resolved": "packages/ui"}
		  }}`)

		Expect(packageNames(got.Dependencies)).To(ConsistOf("@floating-ui/core", "axios", "bar", "react", "typescript"))
		axios := named(got.Dependencies, "axios")
		Expect(axios.Package.Version).To(Equal("1.13.6"))
		Expect(axios.Locked).To(BeTrue())
		Expect(axios.Direct).To(BeTrue())
		Expect(named(got.Dependencies, "@floating-ui/core").Direct).To(BeFalse(), "installed, but not asked for")
		Expect(named(got.Dependencies, "typescript").Direct).To(BeFalse(), "a development dependency")
		Expect(named(got.Dependencies, "bar").Package.Version).To(Equal("2.0.0"), "a nested install")
	})

	It("reads pnpm-lock.yaml:each importer's dependencies and everything resolved", func() {
		got := parse(manifest.PnpmLock{}, "pnpm-lock.yaml", `lockfileVersion: '9.0'

importers:

  .:
    devDependencies:
      turbo:
        specifier: ^2.7.1
        version: 2.7.1
      eslint:
        specifier: ^9.39.2
        version: 9.39.2(jiti@2.6.1)

  apps/web:
    dependencies:
      axios:
        specifier: ^1.13.2
        version: 1.13.2
      ui:
        specifier: workspace:*
        version: link:../../packages/ui

packages:

  '@adraffy/ens-normalize@1.10.1':
    resolution: {integrity: sha512-96Z2}

  axios@1.13.2:
    resolution: {integrity: sha512-aaaa}
`)
		axios := named(got.Dependencies, "axios")
		Expect(axios.Package.Version).To(Equal("1.13.2"))
		Expect(axios.Locked).To(BeTrue())
		Expect(axios.Direct).To(BeTrue())
		Expect(axios.ManifestPath).To(Equal("pnpm-lock.yaml (apps/web)"))
		Expect(named(got.Dependencies, "eslint").Package.Version).To(Equal("9.39.2"), "the peer suffix is not part of the version")
		Expect(named(got.Dependencies, "turbo").Direct).To(BeFalse())
		Expect(named(got.Dependencies, "@adraffy/ens-normalize").Package.Version).To(Equal("1.10.1"), "transitive, at an exact version")
		Expect(packageNames(got.Dependencies)).ToNot(ContainElement("ui"), "a workspace link is not a registry package")
	})

	It("reads Cargo.lock, skipping the workspace's own crates", func() {
		got := parse(manifest.CargoLock{}, "Cargo.lock", `version = 3

[[package]]
name = "ledger-core"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)
		Expect(packageNames(got.Dependencies)).To(Equal([]string{"serde"}))
		Expect(got.Dependencies[0].Package.Version).To(Equal("1.0.197"))
		Expect(got.Dependencies[0].Locked).To(BeTrue())
	})

	It("reads poetry.lock, normalising names as PyPI does", func() {
		got := parse(manifest.PoetryLock{}, "poetry.lock", `[[package]]
name = "Flask"
version = "3.0.2"

[[package]]
name = "python_dateutil"
version = "2.9.0"
`)
		Expect(packageNames(got.Dependencies)).To(ConsistOf("flask", "python-dateutil"))
		Expect(named(got.Dependencies, "flask").Package.Version).To(Equal("3.0.2"))
		Expect(named(got.Dependencies, "flask").Locked).To(BeTrue())
	})

	It("reads composer.lock", func() {
		got := parse(manifest.ComposerLock{}, "composer.lock", `{
		  "packages": [{"name": "Laravel/Framework", "version": "v10.48.2"}],
		  "packages-dev": [{"name": "phpunit/phpunit", "version": "10.5.10"}]}`)
		Expect(named(got.Dependencies, "laravel/framework").Package.Version).To(Equal("v10.48.2"))
		Expect(named(got.Dependencies, "laravel/framework").Locked).To(BeTrue())
		Expect(named(got.Dependencies, "phpunit/phpunit").ManifestPath).To(Equal("composer.lock (dev)"))
	})

	It("marks Gemfile.lock versions as locked", func() {
		got := parse(manifest.GemfileLock{}, "Gemfile.lock", `GEM
  specs:
    rack (2.2.6)

DEPENDENCIES
  rack
`)
		Expect(got.Dependencies[0].Locked).To(BeTrue())
	})

	It("reads a lockfile before the manifest beside it", func() {
		found, _ := manifest.Discover([]string{
			"package.json", "package-lock.json", "apps/web/package.json", "apps/web/pnpm-lock.yaml",
		}, manifest.Parsers())

		paths := []string{}
		for _, f := range found {
			paths = append(paths, f.Path)
		}
		Expect(paths).To(Equal([]string{
			"package-lock.json", "package.json", "apps/web/pnpm-lock.yaml", "apps/web/package.json"}))
	})
})
