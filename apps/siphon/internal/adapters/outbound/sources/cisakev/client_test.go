package cisakev_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/cisakev"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/sourcehttp"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

const sample = `{
  "catalogVersion": "2026.08.27",
  "vulnerabilities": [
    {"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j2",
     "vulnerabilityName":"Apache Log4j2 RCE","dateAdded":"2021-12-10",
     "shortDescription":"JNDI features do not protect against attacker controlled LDAP.",
     "requiredAction":"Apply updates per vendor instructions.",
     "knownRansomwareCampaignUse":"Known","notes":"https://example.test/kev"},
    {"cveID":"CVE-2019-0001","vendorProject":"Old","product":"Thing",
     "vulnerabilityName":"Ancient","dateAdded":"2019-01-01","shortDescription":"old"}
  ]
}`

func serve(body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
}

var _ = Describe("CISA KEV adapter", func() {
	ctx := context.Background()

	It("maps catalog entries into domain signals", func() {
		srv := serve(sample)
		defer srv.Close()

		c := cisakev.New(srv.URL, sourcehttp.WithHTTPClient(srv.Client()))
		Expect(c.Kind()).To(Equal(valueobject.SourceKindCISAKEV))

		got, err := c.Fetch(ctx, time.Time{})
		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(HaveLen(2))

		Expect(got[0].CVEID).To(Equal("CVE-2021-44228"))
		Expect(got[0].Title).To(Equal("Apache Log4j2 RCE"))
		Expect(got[0].Description).To(ContainSubstring("Required action"))
		Expect(got[0].Description).To(ContainSubstring("ransomware"))
		Expect(got[0].References).To(ContainElement("https://example.test/kev"))
		Expect(got[0].PublishedAt.Year()).To(Equal(2021))
	})

	It("filters out entries added before `since`", func() {
		srv := serve(sample)
		defer srv.Close()

		got, err := cisakev.New(srv.URL, sourcehttp.WithHTTPClient(srv.Client())).
			Fetch(ctx, time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC))

		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(HaveLen(1))
		Expect(got[0].CVEID).To(Equal("CVE-2021-44228"))
	})

	It("errors on a bad response", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "nope", http.StatusBadRequest)
		}))
		defer srv.Close()

		_, err := cisakev.New(srv.URL, sourcehttp.WithHTTPClient(srv.Client())).Fetch(ctx, time.Time{})
		Expect(err).To(HaveOccurred())
	})
})
