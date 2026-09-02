package mitre_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/mitre"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/sourcehttp"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

const deltaJSON = `{"new":[{"cveId":"CVE-2026-1111","dateUpdated":"2026-09-01T10:00:00.000Z"}],
                    "updated":[{"cveId":"CVE-2026-2222","dateUpdated":"2026-09-01T11:00:00.000Z"}]}`

const recordJSON = `{
 "cveMetadata":{"cveId":"CVE-2026-1111","datePublished":"2026-08-30T00:00:00.000Z",
                "dateUpdated":"2026-09-01T10:00:00.000Z"},
 "containers":{"cna":{"title":"Buffer overflow in Foo",
   "descriptions":[{"lang":"es","value":"desbordamiento"},{"lang":"en","value":"A buffer overflow."}],
   "references":[{"url":"https://example.test/adv"}],
   "metrics":[{"cvssV3_1":{"version":"3.1","baseScore":8.8,"vectorString":"CVSS:3.1/AV:N","baseSeverity":"HIGH"}}]}}}`

var _ = Describe("MITRE adapter", func() {
	ctx := context.Background()

	It("reads the delta feed and hydrates each changed record", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "delta") {
				_, _ = w.Write([]byte(deltaJSON))
				return
			}
			_, _ = w.Write([]byte(recordJSON))
		}))
		defer srv.Close()

		c := mitre.New(srv.URL+"/api", sourcehttp.WithHTTPClient(srv.Client())).
			WithDeltaURL(srv.URL + "/delta.json")
		Expect(c.Kind()).To(Equal(valueobject.SourceKindMITRE))

		got, err := c.Fetch(ctx, time.Time{})
		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(HaveLen(2)) // one new + one updated

		Expect(got[0].CVEID).To(Equal("CVE-2026-1111"))
		Expect(got[0].Title).To(Equal("Buffer overflow in Foo"))
		Expect(got[0].Description).To(Equal("A buffer overflow.")) // english preferred
		Expect(got[0].Scores).To(HaveLen(1))
		Expect(got[0].Scores[0].Severity).To(Equal(model.SeverityHigh))
		Expect(got[0].References).To(ContainElement("https://www.cve.org/CVERecord?id=CVE-2026-1111"))
	})

	It("skips records that cannot be hydrated instead of failing the poll", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "delta") {
				_, _ = w.Write([]byte(deltaJSON))
				return
			}
			http.Error(w, "not found", http.StatusNotFound)
		}))
		defer srv.Close()

		got, err := mitre.New(srv.URL+"/api", sourcehttp.WithHTTPClient(srv.Client())).
			WithDeltaURL(srv.URL+"/delta.json").Fetch(ctx, time.Time{})

		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(BeEmpty())
	})
})
