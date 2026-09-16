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

// These specs need a real Elasticsearch: task test:go:integration sets
// CORTEX_TEST_ELASTICSEARCH_URL.
var _ = Describe("search index alias (integration)", func() {
	var (
		ctx  = context.Background()
		url  string
		name string
	)

	BeforeEach(func() {
		url = os.Getenv("CORTEX_TEST_ELASTICSEARCH_URL")
		if url == "" {
			Skip("set CORTEX_TEST_ELASTICSEARCH_URL to run the alias specs")
		}
		// A name per spec: these assert on which concrete index the name
		// resolves to, and a leftover from another spec is indistinguishable
		// from the bug they are looking for.
		name = fmt.Sprintf("hyperion-alias-test-%d", time.Now().UnixNano())

		DeferCleanup(func() {
			for _, suffix := range []string{"", "-000001", "-000002"} {
				req, err := http.NewRequest(http.MethodDelete, url+"/"+name+suffix, nil)
				Expect(err).NotTo(HaveOccurred())
				resp, err := http.DefaultClient.Do(req)
				if err == nil {
					_ = resp.Body.Close()
				}
			}
		})
	})

	It("creates a numbered index with the alias pointing at it", func() {
		index := elasticsearch.New(nil, url, name)
		Expect(index.Ready(ctx)).To(Succeed())

		concrete, aliased, err := index.Resolved(ctx)
		Expect(err).NotTo(HaveOccurred())
		// A fresh cluster gets the shape a mapping change can be swapped in:
		// the name is an alias, not an index.
		Expect(aliased).To(BeTrue())
		Expect(concrete).To(Equal(name + "-000001"))
	})

	It("moves the alias to the next index and keeps every document", func() {
		index := elasticsearch.New(nil, url, name)
		Expect(index.Ready(ctx)).To(Succeed())

		for _, id := range []string{"CVE-2021-44228", "CVE-2014-0160", "GHSA-jfh8-c2jp-5v3q"} {
			Expect(index.Index(ctx, model.Vulnerability{
				CVEID:   id,
				Title:   "load bearing",
				Sources: []string{"nvd"},
				Scores:  []model.CVSS{{Version: "3.1", BaseScore: 10, Severity: model.SeverityCritical}},
			})).To(Succeed())
		}

		from, to, err := index.Swap(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(from).To(Equal(name + "-000001"))
		Expect(to).To(Equal(name + "-000002"))

		concrete, aliased, err := index.Resolved(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(aliased).To(BeTrue())
		Expect(concrete).To(Equal(name + "-000002"))

		// The documents came with it. A swap that lost them would be a rebuild
		// with extra steps.
		ids, err := index.IDs(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(ids).To(ConsistOf("CVE-2021-44228", "CVE-2014-0160", "GHSA-jfh8-c2jp-5v3q"))
	})

	It("indexes a whole-number score without inferring the wrong type for it", func() {
		index := elasticsearch.New(nil, url, name)
		Expect(index.Ready(ctx)).To(Succeed())

		// A score of exactly 10 used to make Elasticsearch infer base_score as
		// a long, and every later decimal was then rejected outright. The
		// order these are written in is the whole test.
		Expect(index.Index(ctx, model.Vulnerability{
			CVEID:  "CVE-2021-44228",
			Scores: []model.CVSS{{Version: "3.1", BaseScore: 10}},
		})).To(Succeed())

		Expect(index.Index(ctx, model.Vulnerability{
			CVEID:  "CVE-2014-0160",
			Scores: []model.CVSS{{Version: "3.1", BaseScore: 9.8}},
		})).To(Succeed())
	})
})
