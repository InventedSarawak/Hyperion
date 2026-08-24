package nvd_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/nvd"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// a trimmed but realistic NVD API 2.0 response.
const sampleResponse = `{
  "resultsPerPage": 1,
  "totalResults": 1,
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2021-44228",
        "published": "2021-12-10T10:15:09.143",
        "lastModified": "2023-04-03T20:15:08.960",
        "descriptions": [
          {"lang": "es", "value": "descripcion"},
          {"lang": "en", "value": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP."}
        ],
        "metrics": {
          "cvssMetricV31": [
            {"cvssData": {"version": "3.1", "baseScore": 10.0, "vectorString": "CVSS:3.1/AV:N", "baseSeverity": "CRITICAL"}}
          ]
        },
        "references": [
          {"url": "https://logging.apache.org/log4j/"},
          {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}
        ]
      }
    }
  ]
}`

var _ = Describe("NVD Client", func() {
	It("maps an NVD response into domain SourceSignals", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(sampleResponse))
		}))
		defer srv.Close()

		client := nvd.New(srv.Client(), srv.URL, "")
		Expect(client.Kind()).To(Equal(valueobject.SourceKindNVD))

		signals, err := client.Fetch(context.Background(), time.Time{})
		Expect(err).ToNot(HaveOccurred())
		Expect(signals).To(HaveLen(1))

		s := signals[0]
		Expect(s.CVEID).To(Equal("CVE-2021-44228"))
		Expect(s.Description).To(ContainSubstring("Apache Log4j2")) // english picked over spanish
		Expect(s.References).To(HaveLen(2))
		Expect(s.Scores).To(HaveLen(1))
		Expect(s.Scores[0].BaseScore).To(Equal(10.0))
		Expect(s.Scores[0].Severity).To(Equal(model.SeverityCritical))
		Expect(s.PublishedAt.Year()).To(Equal(2021))
	})

	It("returns an error on a non-200 status", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "rate limited", http.StatusForbidden)
		}))
		defer srv.Close()

		_, err := nvd.New(srv.Client(), srv.URL, "").Fetch(context.Background(), time.Time{})
		Expect(err).To(HaveOccurred())
	})

	It("sends the incremental date filter when since is set", func() {
		var gotQuery string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotQuery = r.URL.RawQuery
			_, _ = w.Write([]byte(`{"vulnerabilities":[]}`))
		}))
		defer srv.Close()

		since := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
		_, err := nvd.New(srv.Client(), srv.URL, "").Fetch(context.Background(), since)
		Expect(err).ToNot(HaveOccurred())
		Expect(gotQuery).To(ContainSubstring("lastModStartDate"))
		Expect(gotQuery).To(ContainSubstring("lastModEndDate"))
	})
})
