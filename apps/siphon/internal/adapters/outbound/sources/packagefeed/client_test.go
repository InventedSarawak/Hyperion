package packagefeed_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/packagefeed"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

const osvQueryJSON = `{"vulns":[
 {"id":"GHSA-aaaa","summary":"Prototype pollution","details":"Details here.",
  "aliases":["CVE-2026-3333"],"modified":"2026-09-01T00:00:00Z","published":"2026-08-01T00:00:00Z",
  "references":[{"type":"WEB","url":"https://example.test/pkg"}],
  "database_specific":{"severity":"HIGH"}},
 {"id":"GHSA-bbbb","summary":"No CVE alias","details":"x",
  "aliases":[],"modified":"2026-09-01T00:00:00Z"}
]}`

var _ = Describe("Package feed adapter", func() {
	ctx := context.Background()

	It("resolves watched packages against OSV and keeps only CVE-aliased records", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(osvQueryJSON))
		}))
		defer srv.Close()

		c := packagefeed.New(srv.URL, []string{"npm:lodash"}, srv.Client())
		Expect(c.Kind()).To(Equal(valueobject.SourceKindPackageFeed))

		got, err := c.Fetch(ctx, time.Time{})
		Expect(err).ToNot(HaveOccurred())

		Expect(got).To(HaveLen(1)) // the alias-less record is skipped
		Expect(got[0].CVEID).To(Equal("CVE-2026-3333"))
		Expect(got[0].Description).To(ContainSubstring("watched package lodash"))
	})

	It("de-duplicates a CVE that affects several watched packages", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(osvQueryJSON))
		}))
		defer srv.Close()

		got, err := packagefeed.New(srv.URL, []string{"npm:lodash", "npm:express"}, srv.Client()).
			Fetch(ctx, time.Time{})

		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(HaveLen(1))
	})

	It("ignores malformed watchlist entries", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"vulns":[]}`))
		}))
		defer srv.Close()

		got, err := packagefeed.New(srv.URL, []string{"no-colon-here"}, srv.Client()).Fetch(ctx, time.Time{})
		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(BeEmpty())
	})
})
