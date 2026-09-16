package elasticsearch_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/elasticsearch"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// Ranking and paging against a real Elasticsearch. Skipped unless
// CORTEX_TEST_ELASTICSEARCH_URL is set; each spec uses a throwaway index.
var _ = Describe("Elasticsearch ranking and paging (integration)", func() {
	var (
		ctx   = context.Background()
		index *elasticsearch.Index
		url   string
		name  string
	)

	BeforeEach(func() {
		url = os.Getenv("CORTEX_TEST_ELASTICSEARCH_URL")
		if url == "" {
			Skip("set CORTEX_TEST_ELASTICSEARCH_URL to run Elasticsearch integration tests")
		}
		name = fmt.Sprintf("hyperion-rank-%d", time.Now().UnixNano())
		index = elasticsearch.New(nil, url, name)
		Expect(index.Ready(ctx)).To(Succeed())

		DeferCleanup(func() {
			req, _ := http.NewRequest(http.MethodDelete, url+"/"+name, nil)
			if resp, err := http.DefaultClient.Do(req); err == nil {
				resp.Body.Close()
			}
		})
	})

	refresh := func() {
		resp, err := http.Post(url+"/"+name+"/_refresh", "application/json", nil)
		Expect(err).ToNot(HaveOccurred())
		resp.Body.Close()
	}
	put := func(v model.Vulnerability) {
		GinkgoHelper()
		Expect(index.Index(ctx, v)).To(Succeed())
	}
	day := func(d int) time.Time { return time.Date(2026, 1, d, 0, 0, 0, 0, time.UTC) }
	ids := func(page model.SearchPage) []string {
		out := make([]string, 0, len(page.Hits))
		for _, h := range page.Hits {
			out = append(out, h.Vulnerability.CVEID)
		}
		return out
	}
	search := func(q model.SearchQuery) model.SearchPage {
		GinkgoHelper()
		page, err := index.Search(ctx, q)
		Expect(err).ToNot(HaveOccurred())
		return page
	}

	It("breaks relevance ties by newest, then by CVE id, so the order is total", func() {
		// Identical text scores identically; without a tiebreaker the order
		// is whatever the index happens to store, and paging repeats or skips.
		for i, d := range []int{3, 9, 5, 9} {
			put(model.Vulnerability{
				CVEID: fmt.Sprintf("CVE-2026-000%d", i), Title: "Prototype Pollution in lodash",
				PublishedAt: day(d),
			})
		}
		refresh()

		page := search(model.SearchQuery{Text: "lodash", Sort: model.SortRelevance, Size: 10})
		Expect(ids(page)).To(Equal([]string{
			"CVE-2026-0001", "CVE-2026-0003", // both 9 Jan: tie broken by id
			"CVE-2026-0002", // 5 Jan
			"CVE-2026-0000", // 3 Jan
		}))
	})

	It("pages through tied results without repeating or skipping any", func() {
		for i := 0; i < 23; i++ {
			put(model.Vulnerability{CVEID: fmt.Sprintf("CVE-2026-%04d", i),
				Title: "Prototype Pollution in lodash", PublishedAt: day(1 + i%3)})
		}
		refresh()

		seen := map[string]int{}
		for offset := 0; offset < 23; offset += 5 {
			for _, id := range ids(search(model.SearchQuery{Text: "lodash", Sort: model.SortRelevance, Size: 5, Offset: offset})) {
				seen[id]++
			}
		}
		Expect(seen).To(HaveLen(23), "every record reached exactly once across pages")
		for id, n := range seen {
			Expect(n).To(Equal(1), "%s appeared on %d pages", id, n)
		}
	})

	It("sorts by publication date, newest first", func() {
		put(model.Vulnerability{CVEID: "CVE-OLD", Title: "lodash flaw", PublishedAt: day(1)})
		put(model.Vulnerability{CVEID: "CVE-NEW", Title: "lodash flaw", PublishedAt: day(20)})
		put(model.Vulnerability{CVEID: "CVE-MID", Title: "lodash flaw", PublishedAt: day(10)})
		refresh()

		page := search(model.SearchQuery{Text: "lodash", Sort: model.SortNewest, Size: 10})
		Expect(ids(page)).To(Equal([]string{"CVE-NEW", "CVE-MID", "CVE-OLD"}))
	})

	It("serves the newest findings for an empty query: the live feed", func() {
		put(model.Vulnerability{CVEID: "CVE-A", Title: "anything", PublishedAt: day(2)})
		put(model.Vulnerability{CVEID: "CVE-B", Title: "something else", PublishedAt: day(7)})
		put(model.Vulnerability{CVEID: "CVE-C", Title: "unrelated", PublishedAt: day(4)})
		refresh()

		page := search(model.SearchQuery{Sort: model.SortNewest, Size: 10})
		Expect(ids(page)).To(Equal([]string{"CVE-B", "CVE-C", "CVE-A"}))
		Expect(page.Total).To(Equal(int64(3)))
	})

	It("puts records with no publication date last rather than first", func() {
		put(model.Vulnerability{CVEID: "CVE-UNDATED", Title: "lodash"})
		put(model.Vulnerability{CVEID: "CVE-DATED", Title: "lodash", PublishedAt: day(1)})
		refresh()

		page := search(model.SearchQuery{Sort: model.SortNewest, Size: 10})
		Expect(ids(page)).To(Equal([]string{"CVE-DATED", "CVE-UNDATED"}))
	})

	It("reports the total, so a client can say how much remains", func() {
		for i := 0; i < 12; i++ {
			put(model.Vulnerability{CVEID: fmt.Sprintf("CVE-T-%02d", i), Title: "lodash", PublishedAt: day(1)})
		}
		refresh()

		page := search(model.SearchQuery{Text: "lodash", Sort: model.SortRelevance, Size: 5})
		Expect(page.Hits).To(HaveLen(5))
		Expect(page.Total).To(Equal(int64(12)))
		Expect(page.TotalIsLowerBound).To(BeFalse())
	})

	It("ranks an advisory that affects the package above one that only uses the word", func() {
		// "next" is Next.js, and also "fix next buffer leak" in a kernel
		// changelog. Text alone scores them the same way; the affected
		// package is what tells them apart.
		put(model.Vulnerability{
			CVEID: "CVE-KERNEL", Title: "CVE-KERNEL", PublishedAt: day(20),
			Description: "smb: client: fix next buffer leak in receive_encrypted_standard(); next next next",
		})
		put(model.Vulnerability{
			CVEID: "CVE-NEXTJS", Title: "Cache confusion in an image optimizer", PublishedAt: day(1),
			Description:      "Responses could be served to the wrong client.",
			AffectedPackages: []valueobject.PackageRef{valueobject.NewPackageRef("npm", "next", "< 14.2.10")},
		})
		refresh()

		page := search(model.SearchQuery{Text: "next", Sort: model.SortRelevance, Size: 10})
		Expect(ids(page)[0]).To(Equal("CVE-NEXTJS"))
	})

	It("finds a record by its exact package key", func() {
		put(model.Vulnerability{CVEID: "CVE-PKG", Title: "some flaw", PublishedAt: day(1),
			AffectedPackages: []valueobject.PackageRef{valueobject.NewPackageRef("npm", "next", "")}})
		put(model.Vulnerability{CVEID: "CVE-OTHER", Title: "next steps", PublishedAt: day(2)})
		refresh()

		page := search(model.SearchQuery{Text: "npm:next", Sort: model.SortRelevance, Size: 10})
		Expect(ids(page)[0]).To(Equal("CVE-PKG"))
	})

	It("returns the affected packages on the hit", func() {
		put(model.Vulnerability{CVEID: "CVE-PKG", Title: "lodash flaw", PublishedAt: day(1),
			AffectedPackages: []valueobject.PackageRef{valueobject.NewPackageRef("npm", "lodash", "< 4.17.21")}})
		refresh()

		hit := search(model.SearchQuery{Text: "lodash", Sort: model.SortRelevance, Size: 1}).Hits[0]
		Expect(hit.Vulnerability.AffectedPackages).To(HaveLen(1))
		Expect(hit.Vulnerability.AffectedPackages[0].Key()).To(Equal("npm:lodash"))
	})

	It("no longer lets fuzziness turn one word into another", func() {
		// AUTO fuzziness on its own allowed "next" to match "text" — a typo
		// nobody made. Requiring the first two characters to match stops that
		// while keeping real typos ("lodahs") working.
		put(model.Vulnerability{CVEID: "CVE-TEXT", Title: "plain text parsing flaw", PublishedAt: day(1)})
		put(model.Vulnerability{CVEID: "CVE-LODASH", Title: "lodash flaw", PublishedAt: day(1)})
		refresh()

		Expect(ids(search(model.SearchQuery{Text: "next", Sort: model.SortRelevance, Size: 10}))).
			ToNot(ContainElement("CVE-TEXT"))
		Expect(ids(search(model.SearchQuery{Text: "lodahs", Sort: model.SortRelevance, Size: 10}))).
			To(ContainElement("CVE-LODASH"))
	})

	It("adds the new fields to an index created before they existed", func() {
		// An index from an older cortex must be upgraded in place, not
		// rebuilt: the fields are added, and new writes are searchable by them.
		legacy := fmt.Sprintf("hyperion-legacy-%d", time.Now().UnixNano())
		DeferCleanup(func() {
			req, _ := http.NewRequest(http.MethodDelete, url+"/"+legacy, nil)
			if resp, err := http.DefaultClient.Do(req); err == nil {
				resp.Body.Close()
			}
		})

		oldMapping := `{"mappings":{"properties":{"cve_id":{"type":"keyword","fields":{"text":{"type":"text"}}},` +
			`"title":{"type":"text"},"description":{"type":"text"},"published_at":{"type":"date"}}}}`
		req, _ := http.NewRequest(http.MethodPut, url+"/"+legacy, strings.NewReader(oldMapping))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		Expect(err).ToNot(HaveOccurred())
		resp.Body.Close()

		upgraded := elasticsearch.New(nil, url, legacy)
		Expect(upgraded.Ready(ctx)).To(Succeed())
		Expect(upgraded.Index(ctx, model.Vulnerability{CVEID: "CVE-LEGACY", Title: "flaw",
			PublishedAt:      day(1),
			AffectedPackages: []valueobject.PackageRef{valueobject.NewPackageRef("npm", "next", "")}})).To(Succeed())
		r, err := http.Post(url+"/"+legacy+"/_refresh", "application/json", nil)
		Expect(err).ToNot(HaveOccurred())
		r.Body.Close()

		page, err := upgraded.Search(ctx, model.SearchQuery{Text: "npm:next", Sort: model.SortRelevance, Size: 5})
		Expect(err).ToNot(HaveOccurred())
		Expect(ids(page)).To(ContainElement("CVE-LEGACY"))
	})

	It("refuses to page beyond the result window instead of erroring deep in the index", func() {
		_, err := index.Search(ctx, model.SearchQuery{Text: "x", Sort: model.SortRelevance, Size: 25, Offset: 9990})
		Expect(err).To(MatchError(ContainSubstring("narrow the query")))
	})
})

var _ = Describe("Elasticsearch ids and deletion (integration)", func() {
	var (
		ctx   = context.Background()
		index *elasticsearch.Index
		url   string
		name  string
	)

	BeforeEach(func() {
		url = os.Getenv("CORTEX_TEST_ELASTICSEARCH_URL")
		if url == "" {
			Skip("set CORTEX_TEST_ELASTICSEARCH_URL to run Elasticsearch integration tests")
		}
		name = fmt.Sprintf("hyperion-ids-%d", time.Now().UnixNano())
		index = elasticsearch.New(nil, url, name)
		Expect(index.Ready(ctx)).To(Succeed())
		DeferCleanup(func() {
			req, _ := http.NewRequest(http.MethodDelete, url+"/"+name, nil)
			if resp, err := http.DefaultClient.Do(req); err == nil {
				resp.Body.Close()
			}
		})
	})

	It("lists every id, past the first page of 1,000", func() {
		// Bulk-load rather than index one at a time: this spec is about the
		// listing walking past a page boundary, not about write speed.
		var bulk strings.Builder
		for i := 0; i < 1203; i++ {
			fmt.Fprintf(&bulk, `{"index":{"_id":"CVE-2026-%05d"}}`+"\n", i)
			fmt.Fprintf(&bulk, `{"cve_id":"CVE-2026-%05d","title":"x"}`+"\n", i)
		}
		resp, err := http.Post(url+"/"+name+"/_bulk?refresh=true", "application/x-ndjson", strings.NewReader(bulk.String()))
		Expect(err).ToNot(HaveOccurred())
		resp.Body.Close()

		ids, err := index.IDs(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(ids).To(HaveLen(1203))
		Expect(ids[0]).To(Equal("CVE-2026-00000"))
		Expect(ids[1202]).To(Equal("CVE-2026-01202"))
	})

	It("deletes a document, and treats an absent one as already deleted", func() {
		Expect(index.Index(ctx, model.Vulnerability{CVEID: "CVE-GONE", Title: "x"})).To(Succeed())
		resp, err := http.Post(url+"/"+name+"/_refresh", "application/json", nil)
		Expect(err).ToNot(HaveOccurred())
		resp.Body.Close()

		Expect(index.Delete(ctx, "CVE-GONE")).To(Succeed())
		Expect(index.Delete(ctx, "CVE-NEVER-EXISTED")).To(Succeed())

		resp, err = http.Post(url+"/"+name+"/_refresh", "application/json", nil)
		Expect(err).ToNot(HaveOccurred())
		resp.Body.Close()
		ids, err := index.IDs(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(ids).ToNot(ContainElement("CVE-GONE"))
	})
})
