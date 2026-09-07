package osint_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/osint"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/sourcehttp"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

const sampleRSS = `<?xml version="1.0"?>
<rss version="2.0"><channel>
 <item>
  <title>RCE in Foo (CVE-2026-1111)</title>
  <link>https://seclists.test/1</link>
  <description>Details mention CVE-2026-1111 and also CVE-2026-2222.</description>
  <pubDate>Mon, 01 Sep 2026 10:00:00 +0000</pubDate>
 </item>
 <item>
  <title>Just chatter, no identifier</title>
  <link>https://seclists.test/2</link>
  <description>nothing here</description>
  <pubDate>Mon, 01 Sep 2026 11:00:00 +0000</pubDate>
 </item>
</channel></rss>`

var _ = Describe("OSINT adapter", func() {
	ctx := context.Background()

	It("emits one signal per CVE mentioned, skipping items with none", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(sampleRSS))
		}))
		defer srv.Close()

		c := osint.New([]string{srv.URL}, sourcehttp.WithHTTPClient(srv.Client()))
		Expect(c.Kind()).To(Equal(valueobject.SourceKindOSINT))

		got, err := c.Fetch(ctx, time.Time{})
		Expect(err).ToNot(HaveOccurred())

		Expect(got).To(HaveLen(2)) // two CVEs from item one; item two has none
		Expect(got[0].CVEID).To(Equal("CVE-2026-1111"))
		Expect(got[1].CVEID).To(Equal("CVE-2026-2222"))
		Expect(got[0].Description).To(ContainSubstring("pre-advisory"))
		Expect(got[0].References).To(ContainElement("https://seclists.test/1"))
	})

	It("errors only when every feed fails", func() {
		bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "gone", http.StatusNotFound)
		}))
		defer bad.Close()

		_, err := osint.New([]string{bad.URL}, sourcehttp.WithHTTPClient(bad.Client())).Fetch(ctx, time.Time{})
		Expect(err).To(HaveOccurred())
	})
})
