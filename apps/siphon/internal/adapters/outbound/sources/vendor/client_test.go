package vendor_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/sourcehttp"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/vendor"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

const sample = `[
 {"CVE":"CVE-2026-1","severity":"important","public_date":"2026-08-01T00:00:00Z",
  "bugzilla_description":"kernel: flaw","cvss3_score":"7.8",
  "cvss3_scoring_vector":"CVSS:3.1/AV:L","CWE":"CWE-125",
  "resource_url":"https://example.test/cve1","affected_packages":["kernel-1.2"],
  "advisories":["RHSA-2026:1234"]},
 {"CVE":"","severity":"low","public_date":"2026-08-02T00:00:00Z"}
]`

var _ = Describe("Vendor advisory adapter (Red Hat)", func() {
	ctx := context.Background()

	It("maps advisories and skips entries with no CVE", func() {
		var gotQuery string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotQuery = r.URL.RawQuery
			_, _ = w.Write([]byte(sample))
		}))
		defer srv.Close()

		c := vendor.New(srv.URL, sourcehttp.WithHTTPClient(srv.Client()))
		Expect(c.Kind()).To(Equal(valueobject.SourceKindVendorAdvisory))

		got, err := c.Fetch(ctx, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC))
		Expect(err).ToNot(HaveOccurred())

		Expect(got).To(HaveLen(1)) // the blank-CVE row is dropped
		Expect(got[0].CVEID).To(Equal("CVE-2026-1"))
		Expect(got[0].Description).To(ContainSubstring("CWE-125"))
		Expect(got[0].Description).To(ContainSubstring("kernel-1.2"))
		Expect(got[0].Scores[0].BaseScore).To(Equal(7.8))
		Expect(got[0].Scores[0].Severity).To(Equal(model.SeverityHigh)) // "important" -> high
		Expect(got[0].References).To(ContainElement("RHSA-2026:1234"))
		Expect(gotQuery).To(ContainSubstring("after=2026-07-01"))
	})

	It("decodes CVSS scores sent as JSON strings (Red Hat's real shape)", func() {
		// Regression: Red Hat returns "7.8", not 7.8. A float64 field fails here.
		const stringScores = `[{"CVE":"CVE-2026-9","severity":"critical",
		 "public_date":"2026-08-05T00:00:00Z","bugzilla_description":"d",
		 "cvss3_score":"9.8","cvss3_scoring_vector":"CVSS:3.1/AV:N"}]`

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(stringScores))
		}))
		defer srv.Close()

		got, err := vendor.New(srv.URL, sourcehttp.WithHTTPClient(srv.Client())).Fetch(ctx, time.Time{})

		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(HaveLen(1))
		Expect(got[0].Scores).To(HaveLen(1))
		Expect(got[0].Scores[0].BaseScore).To(Equal(9.8))
	})

	It("tolerates null scores", func() {
		const nullScores = `[{"CVE":"CVE-2026-10","severity":"low",
		 "public_date":"2026-08-05T00:00:00Z","bugzilla_description":"d",
		 "cvss_score":null,"cvss3_score":null}]`

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(nullScores))
		}))
		defer srv.Close()

		got, err := vendor.New(srv.URL, sourcehttp.WithHTTPClient(srv.Client())).Fetch(ctx, time.Time{})

		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(HaveLen(1))
		Expect(got[0].Scores).To(BeEmpty())
	})
})
