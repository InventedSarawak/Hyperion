package gsd_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/gsd"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/sourcehttp"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

const deltaJSON = `{"new":[{"cveId":"CVE-2026-1111","dateUpdated":"2026-09-01T10:00:00.000Z"}],"updated":[]}`

const osvJSON = `{"id":"CVE-2026-1111","summary":"Foo RCE","details":"Detailed description.",
 "aliases":["GHSA-xxxx"],"modified":"2026-09-01T10:00:00Z","published":"2026-08-30T00:00:00Z",
 "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L"}],
 "references":[{"type":"WEB","url":"https://example.test/osv"}],
 "database_specific":{"severity":"HIGH"}}`

var _ = Describe("GSD/OSV adapter", func() {
	ctx := context.Background()

	It("resolves changed CVE ids through OSV", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "delta") {
				_, _ = w.Write([]byte(deltaJSON))
				return
			}
			_, _ = w.Write([]byte(osvJSON))
		}))
		defer srv.Close()

		c := gsd.New(srv.URL+"/v1", sourcehttp.WithHTTPClient(srv.Client())).
			WithDeltaURL(srv.URL + "/delta.json")
		Expect(c.Kind()).To(Equal(valueobject.SourceKindGSD))

		got, err := c.Fetch(ctx, time.Time{})
		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(HaveLen(1))

		Expect(got[0].CVEID).To(Equal("CVE-2026-1111"))
		Expect(got[0].Title).To(ContainSubstring("OSV/GSD"))
		Expect(got[0].Description).To(Equal("Detailed description."))
		Expect(got[0].References).To(ContainElement("https://example.test/osv"))
	})

	It("skips ids OSV does not carry", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "delta") {
				_, _ = w.Write([]byte(deltaJSON))
				return
			}
			http.Error(w, "not found", http.StatusNotFound)
		}))
		defer srv.Close()

		got, err := gsd.New(srv.URL+"/v1", sourcehttp.WithHTTPClient(srv.Client())).
			WithDeltaURL(srv.URL+"/delta.json").Fetch(ctx, time.Time{})

		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(BeEmpty())
	})
})
