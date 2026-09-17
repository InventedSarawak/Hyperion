package elasticsearch_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/elasticsearch"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	cfg "github.com/inventedsarawak/hyperion/apps/cortex/internal/platform/config"
)

var _ = Describe("Relevance floor (integration)", func() {
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
		name = fmt.Sprintf("hyperion-floor-%d", time.Now().UnixNano())
		index = elasticsearch.New(nil, url, name)
		Expect(index.Ready(ctx)).To(Succeed())
		DeferCleanup(func() {
			req, _ := http.NewRequest(http.MethodDelete, url+"/"+name, nil)
			if resp, err := http.DefaultClient.Do(req); err == nil {
				resp.Body.Close()
			}
		})

		// One record squarely about the thing, and a long tail that merely
		// brushes past the word — which is the shape of the real corpus:
		// searching "react" matched 4,274 records and meant about 1,800.
		Expect(index.Index(ctx, model.Vulnerability{
			CVEID: "CVE-2026-0001", Title: "Remote code execution in Widget",
			Description: "A flaw in Widget allows remote code execution in Widget deployments of Widget.",
		})).To(Succeed())
		for i := range 20 {
			Expect(index.Index(ctx, model.Vulnerability{
				CVEID:       fmt.Sprintf("CVE-2026-1%03d", i),
				Title:       fmt.Sprintf("Unrelated issue %d", i),
				Description: "A changelog entry that happens to mention widget once, in passing.",
			})).To(Succeed())
		}
		resp, err := http.Post(url+"/"+name+"/_refresh", "application/json", nil)
		Expect(err).ToNot(HaveOccurred())
		resp.Body.Close()
	})

	search := func(i *elasticsearch.Index, text string) model.SearchPage {
		GinkgoHelper()
		page, err := i.Search(ctx, model.SearchQuery{Text: text, Sort: model.SortRelevance, Size: 50})
		Expect(err).ToNot(HaveOccurred())
		return page
	}

	It("drops the weak tail of a query", func() {
		all := search(index.WithRelevanceFloor(0), "widget")
		Expect(all.Total).To(BeNumerically("==", 21), "everything that matches at all")

		kept := search(index.WithRelevanceFloor(0.15), "widget")
		Expect(kept.Total).To(BeNumerically("<", all.Total))
		Expect(kept.Hits[0].Vulnerability.CVEID).To(Equal("CVE-2026-0001"))
	})

	It("keeps the best hit however high the floor", func() {
		// The floor is a share of the query's own best score, so the record
		// that set it always clears it. A query can be narrowed to nothing
		// but never to nothing-at-all.
		page := search(index.WithRelevanceFloor(0.99), "widget")
		Expect(page.Hits).ToNot(BeEmpty())
		Expect(page.Hits[0].Vulnerability.CVEID).To(Equal("CVE-2026-0001"))
	})

	It("does not filter the unqueried feed", func() {
		// Nothing was typed, so there is no best score to be a share of —
		// and "the latest findings" must never be a subset of themselves.
		page, err := index.WithRelevanceFloor(0.15).Search(ctx,
			model.SearchQuery{Sort: model.SortNewest, Size: 50})
		Expect(err).ToNot(HaveOccurred())
		Expect(page.Total).To(BeNumerically("==", 21))
	})

	It("finds nothing when nothing matches", func() {
		Expect(search(index.WithRelevanceFloor(0.15), "zzzznomatch").Hits).To(BeEmpty())
	})
})

var _ = Describe("Relevance floor default", func() {
	It("is the same number config hands the adapter", func() {
		// config must not import an adapter, so the constant exists twice.
		// This is what keeps the copies honest.
		Expect(cfg.DefaultRelevanceFloor).To(Equal(elasticsearch.DefaultRelevanceFloor))
	})
})
