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

	It("activates every source by default, since none strictly require a key", func() {
		reg := sources.Build(config.Load(), nil)

		Expect(reg.ActiveClients()).To(HaveLen(10))
		Expect(reg.ActiveKinds()).To(ConsistOf(
			"nvd", "github_advisory", "cisa_kev", "exploit_db", "mitre",
			"vendor_advisory", "osint", "package_feed", "shodan", "gsd",
		))
		Expect(reg.InactiveReasons()).To(BeEmpty())
	})

	It("wires each active client to its own source kind", func() {
		reg := sources.Build(config.Load(), nil)

		kinds := make([]valueobject.SourceKind, 0, 10)
		for _, c := range reg.ActiveClients() {
			kinds = append(kinds, c.Kind())
		}
		Expect(kinds).To(ConsistOf(valueobject.AllSourceKinds()))
	})

	It("deactivates a source when disabled in config", func() {
		cfg := config.Load()
		cfg.NVD.Enabled = false
		cfg.Shodan.Enabled = false

		reg := sources.Build(cfg, nil)
		Expect(reg.ActiveKinds()).ToNot(ContainElement("nvd"))
		Expect(reg.ActiveKinds()).ToNot(ContainElement("shodan"))
		Expect(reg.ActiveClients()).To(HaveLen(8))
		Expect(reg.InactiveReasons()["nvd"]).To(ContainSubstring("SIPHON_NVD_ENABLED=false"))
		Expect(reg.InactiveReasons()["shodan"]).To(ContainSubstring("SIPHON_SHODAN_ENABLED=false"))
	})

	It("notes degraded rate limits when an optional credential is absent", func() {
		cfg := config.Load()
		cfg.NVD.APIKey = ""
		cfg.GitHub.Token = ""

		notes := map[string]string{}
		for _, s := range sources.Build(cfg, nil).Statuses() {
			notes[s.Kind.String()] = s.Note
		}
		Expect(notes["nvd"]).To(ContainSubstring("SIPHON_NVD_API_KEY"))
		Expect(notes["github_advisory"]).To(ContainSubstring("SIPHON_GITHUB_TOKEN"))
	})

	It("drops the rate-limit note once the optional credential is supplied", func() {
		cfg := config.Load()
		cfg.NVD.APIKey = "a-key"
		cfg.GitHub.Token = "a-token"

		notes := map[string]string{}
		for _, s := range sources.Build(cfg, nil).Statuses() {
			notes[s.Kind.String()] = s.Note
		}
		Expect(notes["nvd"]).To(BeEmpty())
		Expect(notes["github_advisory"]).To(BeEmpty())
	})

	It("marks credential-free sources as needing none", func() {
		byKind := map[string]sources.Status{}
		for _, s := range sources.Build(config.Load(), nil).Statuses() {
			byKind[s.Kind.String()] = s
		}
		Expect(byKind["cisa_kev"].NeedsNo).To(BeTrue())
		Expect(byKind["shodan"].NeedsNo).To(BeTrue()) // free CVEDB, no key
		Expect(byKind["nvd"].NeedsNo).To(BeFalse())   // key optional but meaningful
	})
})
