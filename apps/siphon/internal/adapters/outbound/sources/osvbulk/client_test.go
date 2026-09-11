package osvbulk_test

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/osvbulk"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// export builds an ecosystem archive the way OSV lays one out: one JSON file
// per record at the root.
func export(records map[string]string) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, body := range records {
		f, err := w.Create(name)
		Expect(err).ToNot(HaveOccurred())
		_, err = f.Write([]byte(body))
		Expect(err).ToNot(HaveOccurred())
	}
	Expect(w.Close()).To(Succeed())
	return buf.Bytes()
}

var npmExport = map[string]string{
	"GHSA-fv66-9v8q-g76r.json": `{"id":"GHSA-fv66-9v8q-g76r","aliases":["CVE-2025-55182"],
	  "summary":"React Server Components are Vulnerable to RCE","published":"2025-12-03T18:00:00Z",
	  "affected":[{"package":{"ecosystem":"npm","name":"react-server-dom-webpack"},
	    "ranges":[{"type":"SEMVER","events":[{"introduced":"19.0.0"},{"fixed":"19.0.1"}]}]}]}`,
	"MAL-2026-2307.json": `{"id":"MAL-2026-2307","aliases":["GHSA-fw8c-xr5c-95f9"],
	  "summary":"Malicious code in axios (npm)","published":"2026-03-31T00:00:00Z",
	  "affected":[{"package":{"ecosystem":"npm","name":"axios"},"versions":["1.14.1"]}]}`,
	"MAL-2026-0001.json": `{"id":"MAL-2026-0001","summary":"typosquat","published":"2026-01-01T00:00:00Z"}`,
	"GHSA-old0-0000-0000.json": `{"id":"GHSA-old0-0000-0000","aliases":["CVE-2012-0001"],
	  "summary":"ancient","published":"2012-01-01T00:00:00Z"}`,
	"GHSA-bad0-0000-0000.json": `{not json`,
}

var _ = Describe("OSV bulk export backfill", func() {
	ctx := context.Background()
	from := time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)

	collect := func(c *osvbulk.Client) ([]model.SourceSignal, error) {
		var got []model.SourceSignal
		err := c.Backfill(ctx, from, func(batch []model.SourceSignal) error {
			got = append(got, batch...)
			return nil
		})
		return got, err
	}

	It("streams every record in the window, keyed and linked to its package", func() {
		var paths []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			paths = append(paths, r.URL.Path)
			_, _ = w.Write(export(npmExport))
		}))
		defer srv.Close()

		c := osvbulk.New(srv.Client(), srv.URL, []string{"npm"})
		Expect(c.Kind()).To(Equal(valueobject.SourceKindPackageFeed))

		got, err := collect(c)
		Expect(err).ToNot(HaveOccurred())
		Expect(paths).To(Equal([]string{"/npm/all.zip"}))

		ids := map[string]model.SourceSignal{}
		for _, s := range got {
			ids[s.CVEID] = s
		}
		// React2Shell under its CVE, the axios compromise under its GHSA id,
		// the typosquat only OSV knows under its MAL id; the pre-window record
		// and the corrupt file are left out.
		Expect(ids).To(HaveLen(3))
		Expect(ids).To(HaveKey("CVE-2025-55182"))
		Expect(ids).To(HaveKey("GHSA-fw8c-xr5c-95f9"))
		Expect(ids).To(HaveKey("MAL-2026-0001"))
		Expect(ids["MAL-2026-0001"].Kind).To(Equal(model.KindMalware))
		Expect(ids["GHSA-fw8c-xr5c-95f9"].Aliases).To(Equal([]string{"MAL-2026-2307"}))
		Expect(ids["CVE-2025-55182"].AffectedPackages[0].Name).To(Equal("react-server-dom-webpack"))
		Expect(ids["CVE-2025-55182"].AffectedPackages[0].Version).To(Equal(">= 19.0.0, < 19.0.1"))
	})

	It("skips an export that cannot be fetched and still reads the others", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/PyPI/") {
				http.Error(w, "gone", http.StatusNotFound)
				return
			}
			_, _ = w.Write(export(npmExport))
		}))
		defer srv.Close()

		got, err := collect(osvbulk.New(srv.Client(), srv.URL, []string{"PyPI", "npm"}))
		Expect(err).To(MatchError(ContainSubstring("PyPI")))
		Expect(got).To(HaveLen(3), "npm is still read after PyPI fails")
	})

	It("stops at once when the consumer fails", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(export(npmExport))
		}))
		defer srv.Close()

		var calls int
		boom := errors.New("broken pipe")
		err := osvbulk.New(srv.Client(), srv.URL, []string{"npm", "PyPI"}).
			Backfill(ctx, from, func([]model.SourceSignal) error { calls++; return boom })

		Expect(err).To(MatchError(boom))
		Expect(calls).To(Equal(1))
	})
})
