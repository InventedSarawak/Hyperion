package sources_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/platform/config"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/platform/sources"
)

var _ = Describe("Source Registry", func() {
	It("reports a status for all ten documented sources", func() {
		reg := sources.Build(config.Load(), nil)
		Expect(reg.Statuses()).To(HaveLen(len(valueobject.AllSourceKinds())))
		Expect(reg.Statuses()).To(HaveLen(10))
	})

	It("activates NVD by default (it needs no credential)", func() {
		cfg := config.Load()
		reg := sources.Build(cfg, nil)

		Expect(reg.ActiveKinds()).To(ContainElement("nvd"))
		Expect(reg.ActiveClients()).To(HaveLen(1))
		Expect(reg.ActiveClients()[0].Kind()).To(Equal(valueobject.SourceKindNVD))
	})

	It("deactivates NVD when disabled in config", func() {
		cfg := config.Load()
		cfg.NVD.Enabled = false

		reg := sources.Build(cfg, nil)
		Expect(reg.ActiveKinds()).ToNot(ContainElement("nvd"))
		Expect(reg.ActiveClients()).To(BeEmpty())
		Expect(reg.InactiveReasons()["nvd"]).To(ContainSubstring("disabled"))
	})

	It("explains why unimplemented sources are inactive", func() {
		reg := sources.Build(config.Load(), nil)
		reasons := reg.InactiveReasons()

		Expect(reasons).To(HaveKey("cisa_kev"))
		Expect(reasons["cisa_kev"]).To(ContainSubstring("not implemented"))
	})

	It("names the missing credential for sources that require one", func() {
		cfg := config.Load()
		cfg.Shodan.APIKey = ""
		cfg.GitHub.Token = ""

		reasons := sources.Build(cfg, nil).InactiveReasons()
		Expect(reasons["shodan"]).To(ContainSubstring("SIPHON_SHODAN_API_KEY"))
		Expect(reasons["github_advisory"]).To(ContainSubstring("SIPHON_GITHUB_TOKEN"))
	})
})
