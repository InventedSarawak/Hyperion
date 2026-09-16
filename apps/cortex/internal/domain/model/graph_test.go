package model_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

func dep(name, version string, direct bool) model.Dependency {
	return model.Dependency{
		Package:      valueobject.NewPackageRef("go", name, version),
		Direct:       direct,
		ManifestPath: "go.mod",
	}
}

var _ = Describe("Repository", func() {
	It("requires both owner and name", func() {
		Expect(model.Repository{Owner: "kubernetes"}.Validate()).
			To(MatchError(model.ErrMissingRepositoryIdentity))
		Expect(model.Repository{Name: "kubernetes"}.Validate()).
			To(MatchError(model.ErrMissingRepositoryIdentity))
		Expect(model.Repository{Owner: "kubernetes", Name: "kubernetes"}.Validate()).To(Succeed())
	})

	It("identifies itself as owner/name", func() {
		Expect(model.Repository{Owner: "gin-gonic", Name: "gin"}.FullName()).To(Equal("gin-gonic/gin"))
	})
})

var _ = Describe("Author", func() {
	It("requires a login", func() {
		Expect(model.Author{Name: "Kubernetes"}.Validate()).To(MatchError(model.ErrMissingAuthorLogin))
		Expect(model.Author{Login: "kubernetes"}.Validate()).To(Succeed())
	})

	It("is optional: an absent author is zero, not invalid input", func() {
		Expect(model.Author{}.IsZero()).To(BeTrue())
		Expect(model.Author{Login: "kubernetes"}.IsZero()).To(BeFalse())
	})
})

var _ = Describe("Library", func() {
	It("drops the version, so every dependant converges on one node", func() {
		a := model.NewLibrary(valueobject.NewPackageRef("npm", "lodash", "4.17.20"))
		b := model.NewLibrary(valueobject.NewPackageRef("npm", "lodash", "4.17.21"))
		Expect(a).To(Equal(b))
		Expect(a.Key()).To(Equal("npm:lodash"))
	})

	It("requires a name", func() {
		Expect(model.Library{Ecosystem: valueobject.EcosystemNPM}.Validate()).
			To(MatchError(model.ErrMissingLibraryName))
	})
})

var _ = Describe("RepositorySnapshot", func() {
	repo := model.Repository{Owner: "gin-gonic", Name: "gin"}

	It("requires the repository to identify itself", func() {
		Expect(model.RepositorySnapshot{}.Validate()).To(MatchError(model.ErrMissingRepositoryIdentity))
		Expect(model.RepositorySnapshot{Repository: repo}.Validate()).To(Succeed())
	})

	It("drops unparseable dependencies instead of discarding the whole manifest", func() {
		snapshot := model.RepositorySnapshot{
			Repository: repo,
			Dependencies: []model.Dependency{
				dep("golang.org/x/net", "v0.17.0", true),
				{Package: valueobject.NewPackageRef("go", "", "v1.0.0")}, // no name
			},
		}
		valid := snapshot.ValidDependencies()
		Expect(valid).To(HaveLen(1))
		Expect(valid[0].Package.Name).To(Equal("golang.org/x/net"))
	})

	It("collapses a library declared twice into one edge", func() {
		snapshot := model.RepositorySnapshot{
			Repository: repo,
			Dependencies: []model.Dependency{
				dep("golang.org/x/net", "v0.17.0", false),
				dep("golang.org/x/net", "v0.17.0", false),
			},
		}
		Expect(snapshot.ValidDependencies()).To(HaveLen(1))
	})

	It("lets a direct declaration win over an indirect one for the same library", func() {
		// go.mod can list a module as indirect and a later read find it
		// promoted to direct; the stronger statement about the repo's own
		// code is the one the graph should keep.
		snapshot := model.RepositorySnapshot{
			Repository: repo,
			Dependencies: []model.Dependency{
				dep("golang.org/x/net", "v0.17.0", false),
				dep("golang.org/x/net", "v0.17.0", true),
			},
		}
		valid := snapshot.ValidDependencies()
		Expect(valid).To(HaveLen(1))
		Expect(valid[0].Direct).To(BeTrue())

		// ...and in the other order, too.
		snapshot.Dependencies = []model.Dependency{
			dep("golang.org/x/net", "v0.17.0", true),
			dep("golang.org/x/net", "v0.17.0", false),
		}
		valid = snapshot.ValidDependencies()
		Expect(valid).To(HaveLen(1))
		Expect(valid[0].Direct).To(BeTrue())
	})
})

var _ = Describe("RepositorySnapshot published library", func() {
	repo := model.Repository{Owner: "gin-gonic", Name: "gin"}

	base := func(deps ...model.Dependency) model.RepositorySnapshot {
		return model.RepositorySnapshot{
			Repository:   repo,
			Publishes:    valueobject.NewPackageRef("go", "github.com/gin-gonic/gin", ""),
			Dependencies: deps,
		}
	}

	It("reports the library the repository ships", func() {
		published, ok := base().PublishedLibrary()
		Expect(ok).To(BeTrue())
		Expect(published.Key()).To(Equal("go:github.com/gin-gonic/gin"))
	})

	It("treats a repository that publishes nothing as valid", func() {
		snapshot := model.RepositorySnapshot{Repository: repo}
		_, ok := snapshot.PublishedLibrary()
		Expect(ok).To(BeFalse())
		Expect(snapshot.Validate()).To(Succeed())
	})

	It("gives the published library only the repository's direct requirements", func() {
		direct := base(
			dep("golang.org/x/net", "v0.17.0", true),
			dep("golang.org/x/sys", "v0.13.0", false),
		).DirectDependencies()

		Expect(direct).To(HaveLen(1))
		Expect(direct[0].Package.Name).To(Equal("golang.org/x/net"))
	})

	It("never lets a module depend on itself", func() {
		direct := base(
			dep("github.com/gin-gonic/gin", "v1.9.1", true),
			dep("golang.org/x/net", "v0.17.0", true),
		).DirectDependencies()

		Expect(direct).To(HaveLen(1))
		Expect(direct[0].Package.Name).To(Equal("golang.org/x/net"))
	})
})

var _ = Describe("RepositorySnapshot duplicate dependencies", func() {
	ref := func(name, version string) valueobject.PackageRef {
		return valueobject.NewPackageRef("npm", name, version)
	}

	It("prefers the version a lockfile records over the range a manifest allows", func() {
		snapshot := model.RepositorySnapshot{
			Repository: model.Repository{Owner: "acme", Name: "app"},
			Dependencies: []model.Dependency{
				{Package: ref("axios", "^1.13.2"), Direct: true, ManifestPath: "package.json"},
				{Package: ref("axios", "1.13.2"), Locked: true, ManifestPath: "pnpm-lock.yaml"},
			},
		}

		got := snapshot.ValidDependencies()
		Expect(got).To(HaveLen(1))
		Expect(got[0].Package.Version).To(Equal("1.13.2"))
		Expect(got[0].Locked).To(BeTrue())
		Expect(got[0].Direct).To(BeTrue(), "the manifest still says it is a direct dependency")
	})

	It("keeps the locked version whichever order the files were read in", func() {
		snapshot := model.RepositorySnapshot{
			Repository: model.Repository{Owner: "acme", Name: "app"},
			Dependencies: []model.Dependency{
				{Package: ref("axios", "1.13.2"), Locked: true, ManifestPath: "pnpm-lock.yaml"},
				{Package: ref("axios", "^1.13.2"), Direct: true, ManifestPath: "package.json"},
			},
		}

		got := snapshot.ValidDependencies()
		Expect(got).To(HaveLen(1))
		Expect(got[0].Package.Version).To(Equal("1.13.2"))
		Expect(got[0].Direct).To(BeTrue())
	})
})

var _ = Describe("BlastRadius", func() {
	It("distinguishes 'nothing exposed' from 'CVE not linked to any library'", func() {
		unlinked := model.BlastRadius{CVEID: "CVE-2021-44228"}
		Expect(unlinked.Linked()).To(BeFalse())
		Expect(unlinked.TotalRepositories()).To(Equal(0))

		linkedButUnused := model.BlastRadius{
			CVEID:              "CVE-2021-44228",
			VulnerablePackages: []valueobject.PackageRef{valueobject.NewPackageRef("maven", "org.apache.logging.log4j:log4j-core", "")},
		}
		Expect(linkedButUnused.Linked()).To(BeTrue())
		Expect(linkedButUnused.TotalRepositories()).To(Equal(0))
	})
})

var _ = Describe("Vulnerability affected packages", func() {
	maven := valueobject.NewPackageRef("maven", "org.apache.logging.log4j:log4j-core", ">= 2.0.1, < 2.15.0")
	npm := valueobject.NewPackageRef("npm", "lodash", "< 4.17.21")

	It("keeps a package linkage that a later source does not report", func() {
		// GitHub names the package; NVD then re-reports the same CVE with no
		// package at all. Losing the link here would silently disconnect the
		// CVE from every repository it reaches.
		fromGitHub := model.Vulnerability{CVEID: "CVE-2021-44228", AffectedPackages: []valueobject.PackageRef{maven}}
		fromNVD := model.Vulnerability{CVEID: "CVE-2021-44228", Description: "updated"}

		merged := fromGitHub.Merge(fromNVD)

		Expect(merged.Description).To(Equal("updated"))
		Expect(merged.AffectedPackages).To(HaveLen(1))
		Expect(merged.AffectedPackages[0].Name).To(Equal(maven.Name))
	})

	It("unions packages reported by different sources", func() {
		a := model.Vulnerability{CVEID: "CVE-1", AffectedPackages: []valueobject.PackageRef{maven}}
		b := model.Vulnerability{CVEID: "CVE-1", AffectedPackages: []valueobject.PackageRef{npm}}

		merged := a.Merge(b)

		Expect(merged.AffectedPackages).To(HaveLen(2))
	})

	It("keys on the library, so one package with two ranges stays one entry", func() {
		other := valueobject.NewPackageRef("maven", "org.apache.logging.log4j:log4j-core", ">= 2.13.0, < 2.16.0")
		a := model.Vulnerability{CVEID: "CVE-1", AffectedPackages: []valueobject.PackageRef{maven}}
		b := model.Vulnerability{CVEID: "CVE-1", AffectedPackages: []valueobject.PackageRef{other}}

		merged := a.Merge(b)

		Expect(merged.AffectedPackages).To(HaveLen(1))
		Expect(merged.AffectedPackages[0].Version).To(Equal(maven.Version), "the first observation's range is kept")
	})

	It("drops references with no name and stays nil when there is nothing to keep", func() {
		a := model.Vulnerability{CVEID: "CVE-1", AffectedPackages: []valueobject.PackageRef{{Ecosystem: valueobject.EcosystemNPM}}}
		merged := a.Merge(model.Vulnerability{CVEID: "CVE-1"})
		Expect(merged.AffectedPackages).To(BeNil())
	})
})

var _ = Describe("Vulnerability titles", func() {
	It("keeps a real title when a later source repeats only the id", func() {
		// The bug behind every number-only row: NVD's placeholder title (the
		// id itself) arrived after GitHub's and replaced it.
		fromGitHub := model.Vulnerability{CVEID: "CVE-2026-1", Title: "Prototype pollution in lodash"}
		fromNVD := model.Vulnerability{CVEID: "CVE-2026-1", Title: "CVE-2026-1", Description: "NVD text"}

		merged := fromGitHub.Merge(fromNVD)

		Expect(merged.Title).To(Equal("Prototype pollution in lodash"))
		Expect(merged.Description).To(Equal("NVD text"))
	})

	It("takes a real title over a record that had none", func() {
		fromNVD := model.Vulnerability{CVEID: "CVE-2026-1", Description: "NVD text"}
		merged := fromNVD.Merge(model.Vulnerability{CVEID: "CVE-2026-1", Title: "Real title"})
		Expect(merged.Title).To(Equal("Real title"))
	})

	It("does not count the id, in any case, as a title", func() {
		Expect(model.Vulnerability{CVEID: "CVE-2026-1", Title: " cve-2026-1 "}.HasTitle()).To(BeFalse())
		Expect(model.Vulnerability{CVEID: "CVE-2026-1"}.HasTitle()).To(BeFalse())
		Expect(model.Vulnerability{CVEID: "CVE-2026-1", Title: "RCE"}.HasTitle()).To(BeTrue())
	})
})

var _ = Describe("Vulnerability references", func() {
	It("accumulates references across feeds instead of replacing them", func() {
		fromGitHub := model.Vulnerability{CVEID: "CVE-1", References: []string{"https://github.com/advisories/GHSA-x", "https://patch"}}
		fromNVD := model.Vulnerability{CVEID: "CVE-1", References: []string{"https://patch", "https://vendor/bulletin"}}

		merged := fromGitHub.Merge(fromNVD)

		Expect(merged.References).To(Equal([]string{
			"https://github.com/advisories/GHSA-x", "https://patch", "https://vendor/bulletin",
		}))
	})
})
