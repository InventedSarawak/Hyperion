package graphql_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	graphqladapter "github.com/inventedsarawak/hyperion/apps/nexus/internal/adapters/inbound/graphql"
	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/model"
)

// stubSearcher stands in for the search use case.
type stubSearcher struct {
	gotTerm string
	result  model.SearchResult
}

func (s *stubSearcher) Handle(_ context.Context, term string, _ int, _ string) (model.SearchResult, error) {
	s.gotTerm = term
	return s.result, nil
}

// post runs a GraphQL query against the handler and returns the decoded body.
func post(handler http.Handler, query string) map[string]any {
	body, err := json.Marshal(map[string]string{"query": query})
	Expect(err).ToNot(HaveOccurred())

	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var out map[string]any
	Expect(json.Unmarshal(rec.Body.Bytes(), &out)).To(Succeed())
	return out
}

var _ = Describe("GraphQL adapter", func() {
	It("resolves a search query into the response shape", func() {
		stub := &stubSearcher{result: model.SearchResult{
			Hits: []model.SearchHit{{
				Vulnerability: model.Vulnerability{
					CVEID:       "CVE-2021-44228",
					Description: "log4shell",
					Scores:      []model.CVSS{{BaseScore: 10, Severity: "CRITICAL"}},
					PublishedAt: time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC),
				},
				Score: 8.5,
			}},
			NextPageToken: "25",
		}}

		schema, err := graphqladapter.NewSchema(stub)
		Expect(err).ToNot(HaveOccurred())

		out := post(graphqladapter.NewHandler(schema),
			`{ search(term: "log4j", pageSize: 5) { hits { score vulnerability { cveId description scores { baseScore severity } } } nextPageToken } }`)

		Expect(out).ToNot(HaveKey("errors"))
		Expect(stub.gotTerm).To(Equal("log4j"))

		data := out["data"].(map[string]any)
		search := data["search"].(map[string]any)
		Expect(search["nextPageToken"]).To(Equal("25"))

		hits := search["hits"].([]any)
		Expect(hits).To(HaveLen(1))

		hit := hits[0].(map[string]any)
		Expect(hit["score"]).To(BeNumerically("==", 8.5))

		vuln := hit["vulnerability"].(map[string]any)
		Expect(vuln["cveId"]).To(Equal("CVE-2021-44228"))
		Expect(vuln["description"]).To(Equal("log4shell"))

		scores := vuln["scores"].([]any)
		Expect(scores[0].(map[string]any)["severity"]).To(Equal("CRITICAL"))
	})

	It("reports a GraphQL error when the required term is missing", func() {
		schema, err := graphqladapter.NewSchema(&stubSearcher{})
		Expect(err).ToNot(HaveOccurred())

		out := post(graphqladapter.NewHandler(schema), `{ search { hits { score } } }`)
		Expect(out).To(HaveKey("errors"))
	})

	It("rejects non-POST requests", func() {
		schema, err := graphqladapter.NewSchema(&stubSearcher{})
		Expect(err).ToNot(HaveOccurred())

		req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
		rec := httptest.NewRecorder()
		graphqladapter.NewHandler(schema).ServeHTTP(rec, req)

		Expect(rec.Code).To(Equal(http.StatusMethodNotAllowed))
	})

	It("serves the playground console", func() {
		req := httptest.NewRequest(http.MethodGet, "/playground", nil)
		rec := httptest.NewRecorder()
		graphqladapter.NewPlaygroundHandler().ServeHTTP(rec, req)

		Expect(rec.Code).To(Equal(http.StatusOK))
		Expect(rec.Body.String()).To(ContainSubstring("Hyperion"))
	})
})
