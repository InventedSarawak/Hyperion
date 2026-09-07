package shodan_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/shodan"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/sourcehttp"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

const sample = `{"cves":[
 {"cve_id":"CVE-2021-44228","summary":"Log4Shell RCE","cvss":9.3,"cvss_version":4.0,
  "cvss_v3":10.0,"cvss_v4":9.3,"epss":0.9744,"kev":true,"ransomware_campaign":"Known",
  "references":["https://example.test/a"],"published_time":"2021-12-10T00:00:00"},
 {"cve_id":"CVE-2015-0001","summary":"old one","cvss":5.0,"cvss_version":3.1,
  "epss":null,"ranking_epss":null,"propose_action":null,"ransomware_campaign":null,
  "cvss_v2":null,"cvss_v3":null,"cvss_v4":null,"kev":false,"published_time":"2015-01-01T00:00:00"}
]}`

var _ = Describe("Shodan CVEDB adapter", func() {
	ctx := context.Background()

	serve := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(sample))
		}))
	}

	It("maps CVEDB records, surfacing EPSS and KEV", func() {
		srv := serve()
		defer srv.Close()

		c := shodan.New(srv.URL, "", sourcehttp.WithHTTPClient(srv.Client()))
		Expect(c.Kind()).To(Equal(valueobject.SourceKindShodan))

		got, err := c.Fetch(ctx, time.Time{})
		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(HaveLen(2))

		Expect(got[0].CVEID).To(Equal("CVE-2021-44228"))
		Expect(got[0].Description).To(ContainSubstring("EPSS"))
		Expect(got[0].Description).To(ContainSubstring("actively exploited"))
		Expect(got[0].Description).To(ContainSubstring("Ransomware"))
		Expect(got[0].Scores[0].BaseScore).To(Equal(9.3)) // prefers the newest revision (v4)
		Expect(got[0].Scores[0].Severity).To(Equal(model.SeverityCritical))
	})

	It("filters records older than `since`", func() {
		srv := serve()
		defer srv.Close()

		got, err := shodan.New(srv.URL, "", sourcehttp.WithHTTPClient(srv.Client())).
			Fetch(ctx, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))

		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(HaveLen(1))
	})

	It("works with no API key (CVEDB is free)", func() {
		srv := serve()
		defer srv.Close()

		_, err := shodan.New(srv.URL, "", sourcehttp.WithHTTPClient(srv.Client())).Fetch(ctx, time.Time{})
		Expect(err).ToNot(HaveOccurred())
	})

	It("tolerates CVEDB's real shape: float versions and null metrics", func() {
		// Regression: cvss_version arrives as 4.0 (a float), and most optional
		// metrics arrive as null. Both broke a naive int/float64 DTO.
		srv := serve()
		defer srv.Close()

		got, err := shodan.New(srv.URL, "", sourcehttp.WithHTTPClient(srv.Client())).Fetch(ctx, time.Time{})

		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(HaveLen(2))

		// The all-null record still maps, falling back to the plain cvss field.
		Expect(got[1].CVEID).To(Equal("CVE-2015-0001"))
		Expect(got[1].Scores).To(HaveLen(1))
		Expect(got[1].Scores[0].BaseScore).To(Equal(5.0))
		Expect(got[1].Description).ToNot(ContainSubstring("EPSS")) // null EPSS is omitted
	})

	It("filters server-side by date rather than sorting by EPSS", func() {
		// Sorting by EPSS returns years-old CVEs that an incremental poll would
		// discard; a date window is what actually yields recent records.
		var gotQuery string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotQuery = r.URL.RawQuery
			_, _ = w.Write([]byte(sample))
		}))
		defer srv.Close()

		_, err := shodan.New(srv.URL, "", sourcehttp.WithHTTPClient(srv.Client())).
			Fetch(ctx, time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC))

		Expect(err).ToNot(HaveOccurred())
		Expect(gotQuery).To(ContainSubstring("start_date=2026-08-01"))
		Expect(gotQuery).To(ContainSubstring("end_date="))
		Expect(gotQuery).ToNot(ContainSubstring("sort_by_epss"))
	})
})
