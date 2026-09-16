package osv_test

import (
	"encoding/json"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/osv"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// decode parses an OSV record the way the HTTP adapters do, so the JSON tags
// are exercised rather than a hand-built struct.
func decode(raw string) osv.Vulnerability {
	var v osv.Vulnerability
	Expect(json.Unmarshal([]byte(raw), &v)).To(Succeed())
	return v
}

var _ = Describe("OSV affected packages", func() {
	It("maps affected packages onto domain references", func() {
		v := decode(`{
		  "id":"GHSA-xxxx","aliases":["CVE-2021-44228"],"summary":"Log4Shell",
		  "modified":"2023-01-01T00:00:00Z",
		  "affected":[
		    {"package":{"ecosystem":"Maven","name":"org.apache.logging.log4j:log4j-core"},
		     "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.0.1"},{"fixed":"2.15.0"}]}]}
		  ]}`)

		signal, ok := osv.ToSourceSignal(v, time.Time{})
		Expect(ok).To(BeTrue())
		Expect(signal.CVEID).To(Equal("CVE-2021-44228"))
		Expect(signal.AffectedPackages).To(HaveLen(1))
		Expect(signal.AffectedPackages[0].Ecosystem).To(Equal(valueobject.EcosystemMaven))
		Expect(signal.AffectedPackages[0].Name).To(Equal("org.apache.logging.log4j:log4j-core"))
		// GitHub's syntax, with the fix as the upper bound.
		Expect(signal.AffectedPackages[0].Version).To(Equal(">= 2.0.1, < 2.15.0"))
	})

	It("renders several spans, open ranges and exact releases", func() {
		v := decode(`{
		  "id":"CVE-2024-0009","modified":"2024-01-01T00:00:00Z",
		  "affected":[
		    {"package":{"ecosystem":"npm","name":"a"},
		     "ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.2.3"},{"introduced":"2.0.0"},{"fixed":"2.0.4"}]}]},
		    {"package":{"ecosystem":"npm","name":"b"},
		     "ranges":[{"type":"SEMVER","events":[{"introduced":"3.0.0"}]}]},
		    {"package":{"ecosystem":"npm","name":"c"},"versions":["1.14.1","0.30.4"]},
		    {"package":{"ecosystem":"npm","name":"d"},
		     "ranges":[{"type":"GIT","events":[{"introduced":"abc123"},{"fixed":"def456"}]}]}
		  ]}`)

		signal, ok := osv.ToSourceSignal(v, time.Time{})
		Expect(ok).To(BeTrue())
		versions := map[string]string{}
		for _, p := range signal.AffectedPackages {
			versions[p.Name] = p.Version
		}
		Expect(versions).To(Equal(map[string]string{
			"a": ">= 1.0.0, < 1.2.3 || >= 2.0.0, < 2.0.4",
			"b": ">= 3.0.0",
			"c": "= 1.14.1 || = 0.30.4",
			"d": "", // commit hashes are not versions
		}))
	})

	It("strips the distribution suffix OSV appends to some ecosystems", func() {
		// OSV writes "Debian:11" and "Alpine:v3.18"; only the registry before
		// the colon identifies the ecosystem.
		v := decode(`{
		  "id":"CVE-2024-0001","modified":"2024-01-01T00:00:00Z",
		  "affected":[{"package":{"ecosystem":"PyPI:extra","name":"requests"}}]}`)

		signal, ok := osv.ToSourceSignal(v, time.Time{})
		Expect(ok).To(BeTrue())
		Expect(signal.AffectedPackages[0].Ecosystem).To(Equal(valueobject.EcosystemPyPI))
	})

	It("collapses repeated entries for the same package", func() {
		v := decode(`{
		  "id":"CVE-2024-0002","modified":"2024-01-01T00:00:00Z",
		  "affected":[
		    {"package":{"ecosystem":"npm","name":"lodash"},
		     "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]},
		    {"package":{"ecosystem":"npm","name":"lodash"},
		     "ranges":[{"type":"SEMVER","events":[{"introduced":"3.0.0"}]}]}
		  ]}`)

		signal, ok := osv.ToSourceSignal(v, time.Time{})
		Expect(ok).To(BeTrue())
		Expect(signal.AffectedPackages).To(HaveLen(1))
		// "introduced":"0" means "from the first release": no lower bound.
		Expect(signal.AffectedPackages[0].Version).To(Equal("< 4.17.21"))
	})

	It("skips entries with no package name", func() {
		v := decode(`{
		  "id":"CVE-2024-0003","modified":"2024-01-01T00:00:00Z",
		  "affected":[{"package":{"ecosystem":"npm","name":""}}]}`)

		signal, ok := osv.ToSourceSignal(v, time.Time{})
		Expect(ok).To(BeTrue())
		Expect(signal.AffectedPackages).To(BeNil())
	})

	It("leaves affected packages nil when the record names none", func() {
		v := decode(`{"id":"CVE-2024-0004","modified":"2024-01-01T00:00:00Z"}`)

		signal, ok := osv.ToSourceSignal(v, time.Time{})
		Expect(ok).To(BeTrue())
		Expect(signal.AffectedPackages).To(BeNil())
	})

	It("keys a record with no CVE on its GHSA id, so GitHub's copy merges with it", func() {
		v := decode(`{"id":"GHSA-only-1234","modified":"2024-01-01T00:00:00Z",
		  "affected":[{"package":{"ecosystem":"npm","name":"lodash"}}]}`)

		signal, ok := osv.ToSourceSignal(v, time.Time{})
		Expect(ok).To(BeTrue())
		Expect(signal.CVEID).To(Equal("GHSA-only-1234"))
	})

	It("leads GitHub-reviewed malware with its GHSA alias and keeps the MAL id", func() {
		v := decode(`{"id":"MAL-2026-2307","aliases":["GHSA-fw8c-xr5c-95f9"],
		  "summary":"Malicious code in axios (npm)","modified":"2026-04-01T00:00:00Z",
		  "affected":[{"package":{"ecosystem":"npm","name":"axios"}}]}`)

		signal, ok := osv.ToSourceSignal(v, time.Time{})
		Expect(ok).To(BeTrue())
		Expect(signal.CVEID).To(Equal("GHSA-fw8c-xr5c-95f9"))
		Expect(signal.Aliases).To(Equal([]string{"MAL-2026-2307"}))
		Expect(signal.Kind).To(Equal(model.KindMalware))
		Expect(signal.Title).To(Equal("Malicious code in axios (npm)"))
	})

	It("rates malware critical and strips OSV's per-source scaffolding from it", func() {
		v := decode(`{"id":"MAL-2026-2307","aliases":["GHSA-fw8c-xr5c-95f9"],"summary":"Malicious code in axios (npm)",
		  "details":"\n---\n_-= Per source details. Do not edit below this line.=-_\n\n## Source: ghsa-malware (bcd851213ecf0f8dc58fe88d79b3d19a59388272b2426097de7edc4c53df5d9e)\nAny computer that has this package installed should be considered fully compromised.\n",
		  "modified":"2026-04-01T00:00:00Z"}`)

		signal, ok := osv.ToSourceSignal(v, time.Time{})
		Expect(ok).To(BeTrue())
		Expect(signal.Scores).To(HaveLen(1))
		Expect(signal.Scores[0].Severity).To(Equal(model.SeverityCritical))
		Expect(signal.Description).To(Equal("## Source: ghsa-malware\nAny computer that has this package installed should be considered fully compromised."))
	})

	It("does not invent a rating for an ordinary unrated advisory", func() {
		v := decode(`{"id":"GHSA-none-0000","aliases":["CVE-2024-0008"],"modified":"2024-01-01T00:00:00Z"}`)
		signal, _ := osv.ToSourceSignal(v, time.Time{})
		Expect(signal.Scores).To(BeEmpty())
	})

	It("prefers the CVE over the GHSA id when a record has both", func() {
		v := decode(`{"id":"GHSA-fv66-9v8q-g76r","aliases":["CVE-2025-55182"],"modified":"2026-01-01T00:00:00Z"}`)

		signal, ok := osv.ToSourceSignal(v, time.Time{})
		Expect(ok).To(BeTrue())
		Expect(signal.CVEID).To(Equal("CVE-2025-55182"))
		Expect(signal.Aliases).To(Equal([]string{"GHSA-fv66-9v8q-g76r"}))
		Expect(signal.Kind).To(Equal(model.KindVulnerability))
	})

	It("keeps the record's own ecosystem id as an alias of its CVE", func() {
		v := decode(`{"id":"PYSEC-2021-19","aliases":["cve-2021-3281","GHSA-xxxx-xxxx-xxxx"],"modified":"2024-01-01T00:00:00Z"}`)

		signal, ok := osv.ToSourceSignal(v, time.Time{})
		Expect(ok).To(BeTrue())
		Expect(signal.CVEID).To(Equal("CVE-2021-3281"))
		Expect(signal.Aliases).To(ConsistOf("PYSEC-2021-19", "GHSA-xxxx-xxxx-xxxx"))
	})

	It("keeps malware only OSV knows, under its MAL id and rated critical", func() {
		v := decode(`{"id":"MAL-2026-9999","modified":"2026-01-01T00:00:00Z",
		  "affected":[{"package":{"ecosystem":"npm","name":"typosquat"}}]}`)

		signal, ok := osv.ToSourceSignal(v, time.Time{})
		Expect(ok).To(BeTrue())
		Expect(signal.CVEID).To(Equal("MAL-2026-9999"))
		Expect(signal.Aliases).To(BeEmpty())
		Expect(signal.Kind).To(Equal(model.KindMalware))
		Expect(signal.Scores[0].Severity).To(Equal(model.SeverityCritical))
	})

	It("keeps an advisory with no CVE, GHSA or MAL under the id it has", func() {
		v := decode(`{"id":"GO-2024-3333","modified":"2024-01-01T00:00:00Z"}`)

		signal, ok := osv.ToSourceSignal(v, time.Time{})
		Expect(ok).To(BeTrue())
		Expect(signal.CVEID).To(Equal("GO-2024-3333"))
		Expect(signal.Kind).To(Equal(model.KindVulnerability))
	})

	It("skips a record that carries no id at all", func() {
		_, ok := osv.ToSourceSignal(decode(`{"summary":"anonymous","modified":"2024-01-01T00:00:00Z"}`), time.Time{})
		Expect(ok).To(BeFalse())
	})

	It("skips a withdrawn advisory", func() {
		v := decode(`{"id":"GHSA-gone-0000","aliases":["CVE-2024-0006"],
		  "modified":"2024-01-01T00:00:00Z","withdrawn":"2024-02-01T00:00:00Z"}`)

		_, ok := osv.ToSourceSignal(v, time.Time{})
		Expect(ok).To(BeFalse())
	})

	It("leaves the title empty rather than substituting the id", func() {
		v := decode(`{"id":"PYSEC-2024-1","aliases":["CVE-2024-0005"],"details":"Only details.","modified":"2024-01-01T00:00:00Z"}`)

		signal, ok := osv.ToSourceSignal(v, time.Time{})
		Expect(ok).To(BeTrue())
		Expect(signal.Title).To(BeEmpty())
		Expect(signal.Description).To(Equal("Only details."))
	})
})
