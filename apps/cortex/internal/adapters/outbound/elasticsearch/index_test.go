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
)

// This suite needs a real Elasticsearch. It is skipped unless
// CORTEX_TEST_ELASTICSEARCH_URL is set, e.g.:
//
//	task infra:up
//	CORTEX_TEST_ELASTICSEARCH_URL=http://localhost:9200 \
//	  go test ./internal/adapters/outbound/elasticsearch/...
var _ = Describe("Elasticsearch Index (integration)", func() {
	var (
		ctx   = context.Background()
		index *elasticsearch.Index
		name  string
	)

	BeforeEach(func() {
		url := os.Getenv("CORTEX_TEST_ELASTICSEARCH_URL")
		if url == "" {
			Skip("set CORTEX_TEST_ELASTICSEARCH_URL to run Elasticsearch integration tests")
		}
		// Use a throwaway index per run so tests never touch real data.
		name = fmt.Sprintf("hyperion-test-%d", time.Now().UnixNano())
		index = elasticsearch.New(nil, url, name)
		Expect(index.Ready(ctx)).To(Succeed())

		DeferCleanup(func() {
			req, _ := http.NewRequest(http.MethodDelete, url+"/"+name, nil)
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		})
	})

	// refresh forces ES to make recent writes visible to search immediately.
	refresh := func() {
		url := os.Getenv("CORTEX_TEST_ELASTICSEARCH_URL")
		resp, err := http.Post(url+"/"+name+"/_refresh", "application/json", nil)
		Expect(err).ToNot(HaveOccurred())
		resp.Body.Close()
	}

	It("indexes a vulnerability and finds it by full-text query", func() {
		Expect(index.Index(ctx, model.Vulnerability{
			CVEID:       "CVE-2021-44228",
			Title:       "log4shell",
			Description: "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP",
			Scores:      []model.CVSS{{Version: "3.1", BaseScore: 10, Severity: model.SeverityCritical}},
			Sources:     []string{"nvd"},
			PublishedAt: time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC),
		})).To(Succeed())
		refresh()

		hits, err := index.Search(ctx, "log4j", 10, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(hits).ToNot(BeEmpty())
		Expect(hits[0].Vulnerability.CVEID).To(Equal("CVE-2021-44228"))
		Expect(hits[0].Score).To(BeNumerically(">", 0))
		Expect(hits[0].Vulnerability.Scores).To(HaveLen(1))
		Expect(hits[0].Vulnerability.PublishedAt.Year()).To(Equal(2021))
	})

	It("finds a document by its exact CVE id", func() {
		Expect(index.Index(ctx, model.Vulnerability{
			CVEID:       "CVE-2023-12345",
			Description: "unrelated text",
		})).To(Succeed())
		refresh()

		hits, err := index.Search(ctx, "CVE-2023-12345", 10, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(hits).ToNot(BeEmpty())
		Expect(hits[0].Vulnerability.CVEID).To(Equal("CVE-2023-12345"))
	})

	It("returns no hits for a query that matches nothing", func() {
		refresh()
		hits, err := index.Search(ctx, "zzzznomatchzzzz", 10, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(hits).To(BeEmpty())
	})

	It("re-indexing the same CVE updates rather than duplicates", func() {
		v := model.Vulnerability{CVEID: "CVE-DUP-1", Description: "first version"}
		Expect(index.Index(ctx, v)).To(Succeed())
		v.Description = "second version"
		Expect(index.Index(ctx, v)).To(Succeed())
		refresh()

		hits, err := index.Search(ctx, "CVE-DUP-1", 10, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(hits).To(HaveLen(1))
		Expect(hits[0].Vulnerability.Description).To(Equal("second version"))
	})
})
