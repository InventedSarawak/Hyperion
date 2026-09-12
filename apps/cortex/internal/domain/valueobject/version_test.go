package valueobject_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vo "github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

var _ = Describe("Version", func() {
	parse := func(s string) vo.Version {
		GinkgoHelper()
		v, ok := vo.ParseVersion(s)
		Expect(ok).To(BeTrue(), s)
		return v
	}

	DescribeTable("orders versions the way registries do",
		func(lower, higher string) {
			Expect(parse(lower).Compare(parse(higher))).To(Equal(-1), "%s < %s", lower, higher)
			Expect(parse(higher).Compare(parse(lower))).To(Equal(1))
		},
		Entry("numerically, not lexically", "1.2.3", "1.2.10"),
		Entry("a pre-release before its release", "1.0.0-alpha", "1.0.0"),
		Entry("numeric pre-release tags numerically", "1.0.0-alpha.2", "1.0.0-alpha.10"),
		Entry("numbers before words", "1.0.0-1", "1.0.0-alpha"),
		Entry("a canary of the next minor after the last patch", "15.5.16", "15.6.0-canary.60"),
		Entry("very large components", "3.14.999999999999", "3.15.0"),
		Entry("a Python release candidate before its release", "1.0rc1", "1.0"),
		Entry("a Python dev build before its alpha", "1.0.dev1", "1.0a1"),
		Entry("a Python alpha before its beta", "1.0a1", "1.0b1"),
		Entry("a Python beta before its release candidate", "1.0b1", "1.0rc1"),
		Entry("a Python post-release after its release", "2.0", "2.0.post1"),
		Entry("a Python post-release before the next release", "2.0.post1", "2.0.1"),
		Entry("a Maven snapshot before its release", "1.0-SNAPSHOT", "1.0"),
		Entry("a Maven beta before its release", "2.0.0.Beta1", "2.0.0"),
	)

	DescribeTable("treats spellings of one release as equal",
		func(a, b string) { Expect(parse(a).Compare(parse(b))).To(BeZero()) },
		Entry("missing components are zero", "2.4", "2.4.0"),
		Entry("a Go v prefix", "v1.2.3", "1.2.3"),
		Entry("build metadata", "1.0.0+build.5", "1.0.0"),
		Entry("Maven's name for a plain release", "5.3.20.RELEASE", "5.3.20"),
		Entry("JBoss's name for a plain release", "3.0.Final", "3.0"),
	)

	It("rejects what is not a version", func() {
		for _, s := range []string{"", "latest", "1.x.y", "abc", "1.2.3-"} {
			_, ok := vo.ParseVersion(s)
			Expect(ok).To(BeFalse(), s)
		}
	})
})

var _ = Describe("JudgeExposure", func() {
	DescribeTable("compares what a manifest declares with what an advisory says is affected",
		func(eco vo.Ecosystem, declared, affected string, want vo.ExposureVerdict) {
			Expect(vo.JudgeExposure(eco, declared, affected)).To(Equal(want), "%s vs %s", declared, affected)
		},
		// Pinned versions: a yes or a no.
		Entry("an exact pin inside the range", vo.EcosystemNPM, "4.17.4", "< 4.17.12", vo.ExposureAffected),
		Entry("an exact pin past the fix", vo.EcosystemNPM, "4.17.21", "< 4.17.12", vo.ExposureNotAffected),
		Entry("a canary newer than the range", vo.EcosystemNPM, "15.6.0-canary.60", ">= 12.2.0, < 15.5.16", vo.ExposureNotAffected),
		Entry("the poisoned release itself", vo.EcosystemNPM, "1.14.1", "= 0.30.4 || = 1.14.1", vo.ExposureAffected),
		Entry("a Go requirement", vo.EcosystemGo, "v1.2.3", ">= 1.2.0, < 1.2.5", vo.ExposureAffected),
		Entry("a Go requirement past the fix", vo.EcosystemGo, "v1.2.5", ">= 1.2.0, < 1.2.5", vo.ExposureNotAffected),
		Entry("either side of an 'or'", vo.EcosystemGo, "v1.8.3", "< 1.7.13 || >= 1.8.0, < 1.8.6", vo.ExposureAffected),

		// Ranges: only as sure as the versions they allow.
		Entry("a caret range entirely below the affected floor", vo.EcosystemNPM, "^5.11.0", "< 5.0.8", vo.ExposureNotAffected),
		Entry("a caret range the fix falls inside", vo.EcosystemNPM, "^5.11.0", ">= 5.2.0, < 5.12.8", vo.ExposurePossible),
		Entry("a caret range wholly affected", vo.EcosystemNPM, "^5.11.0", "< 7.1.0", vo.ExposureAffected),
		Entry("every version affected", vo.EcosystemNPM, "^2.0.0", ">= 0", vo.ExposureAffected),
		Entry("a range that may install the poisoned release", vo.EcosystemNPM, "^1.14.0", "= 0.30.4 || = 1.14.1", vo.ExposurePossible),
		Entry("caret on a zero major stays on its minor", vo.EcosystemNPM, "^0.2.3", ">= 0.3.0", vo.ExposureNotAffected),
		Entry("tilde stays on its minor", vo.EcosystemNPM, "~1.2.3", ">= 1.3.0", vo.ExposureNotAffected),
		Entry("tilde overlapping a fix", vo.EcosystemNPM, "~1.2.3", "< 1.2.10", vo.ExposurePossible),
		Entry("an x-range", vo.EcosystemNPM, "1.x", ">= 1.5.0", vo.ExposurePossible),
		Entry("a hyphen range inside", vo.EcosystemNPM, "1.2.3 - 1.4.0", "< 1.5.0", vo.ExposureAffected),
		Entry("explicit bounds inside", vo.EcosystemNPM, ">=1.0.0 <1.1.0", "< 2.0.0", vo.ExposureAffected),
		Entry("a caret range does not reach the next major's pre-releases", vo.EcosystemNPM, "^1.2.3", "= 2.0.0-rc.1", vo.ExposureNotAffected),
		Entry("any version", vo.EcosystemNPM, "*", "< 1.0.0", vo.ExposurePossible),
		Entry("an npm alias", vo.EcosystemNPM, "npm:lodash@^4.17.0", "< 4.17.12", vo.ExposurePossible),

		// Every registry's own grammar.
		Entry("Python: an exact pin inside the range", vo.EcosystemPyPI, "==2.31.0", "< 2.32.0", vo.ExposureAffected),
		Entry("Python: an exact pin past the fix", vo.EcosystemPyPI, "==3.0.3", "< 3.0.3", vo.ExposureNotAffected),
		Entry("Python: a compatible release spanning the fix", vo.EcosystemPyPI, "~=2.28", ">= 2.3.0, < 2.32.0", vo.ExposurePossible),
		Entry("Python: an unpinned requirement", vo.EcosystemPyPI, "", "< 1.0.0", vo.ExposurePossible),
		Entry("Python: bounds inside the range", vo.EcosystemPyPI, ">=1.0,<2.0", "< 3.0", vo.ExposureAffected),
		Entry("Python: a prefix match past the range", vo.EcosystemPyPI, "==1.2.*", ">= 1.3.0", vo.ExposureNotAffected),
		Entry("Python: an advisory range with a release candidate", vo.EcosystemPyPI, "==2.0rc1", ">= 2.0rc1, < 2.0", vo.ExposureAffected),
		Entry("Cargo: a bare version is a caret requirement", vo.EcosystemCargo, "1.2", ">= 1.3.0", vo.ExposurePossible),
		Entry("Cargo: an exact requirement", vo.EcosystemCargo, "=1.2.0", "< 1.2.1", vo.ExposureAffected),
		Entry("Cargo: caret on a zero major stays on its minor", vo.EcosystemCargo, "0.4", ">= 0.5.0", vo.ExposureNotAffected),
		Entry("RubyGems: pessimistic on the minor", vo.EcosystemRubyGems, "~> 7.0", ">= 7.1.0", vo.ExposurePossible),
		Entry("RubyGems: pessimistic on the patch", vo.EcosystemRubyGems, "~> 7.0.4", ">= 7.1.0", vo.ExposureNotAffected),
		Entry("RubyGems: a locked version", vo.EcosystemRubyGems, "7.0.4", "< 7.0.5", vo.ExposureAffected),
		Entry("Maven: a version is what gets built", vo.EcosystemMaven, "2.14.1", ">= 2.0.0, < 2.15.0", vo.ExposureAffected),
		Entry("Maven: a range spanning the fix", vo.EcosystemMaven, "[2.0,2.17)", "< 2.15.0", vo.ExposurePossible),
		Entry("Maven: a qualified release", vo.EcosystemMaven, "5.3.20.RELEASE", ">= 5.3.0, < 5.3.33", vo.ExposureAffected),
		Entry("Maven: an unresolved property", vo.EcosystemMaven, "", "< 1.0", vo.ExposureUnknown),
		Entry("NuGet: a version is what gets restored", vo.EcosystemNuGet, "13.0.1", "< 13.0.2", vo.ExposureAffected),
		Entry("Composer: caret spanning the fix", vo.EcosystemPackagist, "^5.4", ">= 5.4.0, < 5.4.40", vo.ExposurePossible),
		Entry("Composer: tilde on the patch stays below the next minor", vo.EcosystemPackagist, "~5.4.10", ">= 5.5.0", vo.ExposureNotAffected),
		Entry("Composer: tilde on the minor reaches the next minor", vo.EcosystemPackagist, "~5.4", ">= 5.5.0", vo.ExposurePossible),
		Entry("Composer: a branch is not a version", vo.EcosystemPackagist, "dev-main", "< 1.0", vo.ExposureUnknown),

		// What cannot be judged is said so, not guessed.
		Entry("a dist-tag", vo.EcosystemNPM, "latest", "< 1.0.0", vo.ExposureUnknown),
		Entry("a git reference", vo.EcosystemNPM, "git+https://github.com/a/b.git", "< 1.0.0", vo.ExposureUnknown),
		Entry("an advisory with no range", vo.EcosystemNPM, "1.0.0", "", vo.ExposureUnknown),
	)

	It("ranks verdicts from harmless to certain", func() {
		Expect(vo.ExposureAffected.Worse(vo.ExposurePossible)).To(BeTrue())
		Expect(vo.ExposurePossible.Worse(vo.ExposureUnknown)).To(BeTrue())
		Expect(vo.ExposureUnknown.Worse(vo.ExposureNotAffected)).To(BeTrue())
		Expect(vo.ExposureUnknown.Exposed()).To(BeTrue(), "what cannot be ruled out is not cleared")
		Expect(vo.ExposureNotAffected.Exposed()).To(BeFalse())
	})
})
