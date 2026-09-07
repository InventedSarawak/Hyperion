package osv_test

import (
	"encoding/json"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/osv"
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
		Expect(signal.AffectedPackages[0].Version).To(Equal("2.0.1"))
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
		// "introduced":"0" means "from the beginning", not a real version.
		Expect(signal.AffectedPackages[0].Version).To(BeEmpty())
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

	It("still rejects a record with no CVE identity", func() {
		v := decode(`{"id":"GHSA-only","modified":"2024-01-01T00:00:00Z",
		  "affected":[{"package":{"ecosystem":"npm","name":"lodash"}}]}`)

		_, ok := osv.ToSourceSignal(v, time.Time{})
		Expect(ok).To(BeFalse())
	})
})
