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
)

var _ = Describe("Elasticsearch finding ids and kinds (integration)", func() {
	var (
		ctx   = context.Background()
		index *elasticsearch.Index
		url   string
		name  string
	)
	onlyVulns := []model.FindingKind{model.KindVulnerability}

	BeforeEach(func() {
		url = os.Getenv("CORTEX_TEST_ELASTICSEARCH_URL")
		if url == "" {
			Skip("set CORTEX_TEST_ELASTICSEARCH_URL to run Elasticsearch integration tests")
		}
		name = fmt.Sprintf("hyperion-test-%d", time.Now().UnixNano())
		index = elasticsearch.New(nil, url, name)
		Expect(index.Ready(ctx)).To(Succeed())
		DeferCleanup(func() {
			req, _ := http.NewRequest(http.MethodDelete, url+"/"+name, nil)
			if resp, err := http.DefaultClient.Do(req); err == nil {
				resp.Body.Close()
			}
		})

		Expect(index.Index(ctx, model.Vulnerability{
			CVEID: "CVE-2021-44228", Aliases: []string{"GHSA-jfh8-c2jp-5v3q"}, Kind: model.KindVulnerability,
			Title: "axios request smuggling", PublishedAt: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		})).To(Succeed())
		Expect(index.Index(ctx, model.Vulnerability{
			CVEID: "GHSA-fw8c-xr5c-95f9", Aliases: []string{"MAL-2026-2307"}, Kind: model.KindMalware,
			Title: "Malicious code in axios", PublishedAt: time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC),
		})).To(Succeed())
		// A document written before kinds existed.
		req, _ := http.NewRequest(http.MethodPut, url+"/"+name+"/_doc/CVE-2000-0001",
			strings.NewReader(`{"cve_id":"CVE-2000-0001","title":"axios legacy record","published_at":"2000-01-01T00:00:00Z"}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		Expect(err).ToNot(HaveOccurred())
		resp.Body.Close()
		resp, err = http.Post(url+"/"+name+"/_refresh", "application/json", nil)
		Expect(err).ToNot(HaveOccurred())
		resp.Body.Close()
	})

	ids := func(page model.SearchPage) []string {
		out := []string{}
		for _, h := range page.Hits {
			out = append(out, h.Vulnerability.CVEID)
		}
		return out
	}

	It("finds a finding by any of its ids, in whatever case it is typed", func() {
		for _, typed := range []string{"ghsa-JFH8-C2JP-5V3Q", "cve-2021-44228", "MAL-2026-2307"} {
			page, err := index.Search(ctx, model.SearchQuery{Text: typed, Sort: model.SortRelevance, Size: 10})
			Expect(err).ToNot(HaveOccurred())
			Expect(page.Hits).ToNot(BeEmpty(), typed)
		}
		page, _ := index.Search(ctx, model.SearchQuery{Text: "GHSA-jfh8-c2jp-5v3q", Sort: model.SortRelevance, Size: 10})
		Expect(page.Hits[0].Vulnerability.CVEID).To(Equal("CVE-2021-44228"))
		Expect(page.Hits[0].Vulnerability.Aliases).To(Equal([]string{"GHSA-jfh8-c2jp-5v3q"}))
	})

	It("keeps malware out when only vulnerabilities are asked for, and returns it when it is", func() {
		page, err := index.Search(ctx, model.SearchQuery{Text: "axios", Sort: model.SortRelevance, Kinds: onlyVulns, Size: 10})
		Expect(err).ToNot(HaveOccurred())
		Expect(ids(page)).To(ConsistOf("CVE-2021-44228", "CVE-2000-0001"), "a record from before kinds counts as a vulnerability")

		page, _ = index.Search(ctx, model.SearchQuery{Text: "axios", Sort: model.SortRelevance, Kinds: []model.FindingKind{model.KindMalware}, Size: 10})
		Expect(ids(page)).To(ConsistOf("GHSA-fw8c-xr5c-95f9"))
		Expect(page.Hits[0].Vulnerability.Kind).To(Equal(model.KindMalware))

		page, _ = index.Search(ctx, model.SearchQuery{Text: "axios", Sort: model.SortRelevance, Size: 10})
		Expect(ids(page)).To(HaveLen(3), "no kinds means every kind")
	})

	It("finds malware by its exact id even while malware is filtered out", func() {
		page, err := index.Search(ctx, model.SearchQuery{Text: "mal-2026-2307", Sort: model.SortRelevance, Kinds: onlyVulns, Size: 10})
		Expect(err).ToNot(HaveOccurred())
		// Near-miss ids ("2026" is one typo from "2021") may follow it.
		Expect(ids(page)).ToNot(BeEmpty())
		Expect(ids(page)[0]).To(Equal("GHSA-fw8c-xr5c-95f9"))
	})

	It("serves the newest-first feed without malware", func() {
		page, err := index.Search(ctx, model.SearchQuery{Sort: model.SortNewest, Kinds: onlyVulns, Size: 10})
		Expect(err).ToNot(HaveOccurred())
		Expect(ids(page)).To(Equal([]string{"CVE-2021-44228", "CVE-2000-0001"}))
	})
})
