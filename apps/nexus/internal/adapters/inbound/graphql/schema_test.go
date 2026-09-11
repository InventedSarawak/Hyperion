package graphql_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/graphql-go/graphql"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	graphqladapter "github.com/inventedsarawak/hyperion/apps/nexus/internal/adapters/inbound/graphql"
	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/model"
)

// stubSearcher stands in for the search use case.
type stubSearcher struct {
	gotKinds []model.FindingKind
	gotSort  model.SearchSort
	gotTerm  string
	result   model.SearchResult
	err      error
}

func (s *stubSearcher) Handle(_ context.Context, term string, sort model.SearchSort, kinds []model.FindingKind, _ int, _ string) (model.SearchResult, error) {
	s.gotTerm, s.gotSort, s.gotKinds = term, sort, kinds
	if s.err != nil {
		return model.SearchResult{}, s.err
	}
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

		schema, err := graphqladapter.NewSchema(stub, &stubBlast{})
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

	It("passes the kinds asked for and returns every id and the kind of each hit", func() {
		stub := &stubSearcher{result: model.SearchResult{Hits: []model.SearchHit{{Vulnerability: model.Vulnerability{
			CVEID: "GHSA-fw8c-xr5c-95f9", Aliases: []string{"MAL-2026-2307"}, Kind: model.KindMalware,
		}}}}}
		schema, err := graphqladapter.NewSchema(stub, &stubBlast{})
		Expect(err).ToNot(HaveOccurred())

		out := post(graphqladapter.NewHandler(schema),
			`{ search(term: "axios", kinds: [MALWARE, VULNERABILITY]) { hits { vulnerability { cveId aliases kind } } } }`)

		Expect(out).ToNot(HaveKey("errors"))
		Expect(stub.gotKinds).To(Equal([]model.FindingKind{model.KindMalware, model.KindVulnerability}))
		vuln := out["data"].(map[string]any)["search"].(map[string]any)["hits"].([]any)[0].(map[string]any)["vulnerability"].(map[string]any)
		Expect(vuln["aliases"]).To(Equal([]any{"MAL-2026-2307"}))
		Expect(vuln["kind"]).To(Equal("MALWARE"))
	})

	It("asks for every kind when the query names none, and reports an unset kind as a vulnerability", func() {
		stub := &stubSearcher{result: model.SearchResult{Hits: []model.SearchHit{{Vulnerability: model.Vulnerability{CVEID: "CVE-2021-44228"}}}}}
		schema, err := graphqladapter.NewSchema(stub, &stubBlast{})
		Expect(err).ToNot(HaveOccurred())

		out := post(graphqladapter.NewHandler(schema), `{ search(term: "log4j") { hits { vulnerability { kind } } } }`)

		Expect(out).ToNot(HaveKey("errors"))
		Expect(stub.gotKinds).To(BeEmpty())
		vuln := out["data"].(map[string]any)["search"].(map[string]any)["hits"].([]any)[0].(map[string]any)["vulnerability"].(map[string]any)
		Expect(vuln["kind"]).To(Equal("VULNERABILITY"))
	})

	It("reports a GraphQL error when a relevance search has no term", func() {
		// The schema accepts a missing term (sort: NEWEST needs none); the
		// use case is what rejects one under relevance, and its error must
		// reach the client rather than an empty result.
		stub := &stubSearcher{err: errors.New("search: term must not be empty when sorting by relevance")}
		schema, err := graphqladapter.NewSchema(stub, &stubBlast{})
		Expect(err).ToNot(HaveOccurred())

		out := post(graphqladapter.NewHandler(schema), `{ search { hits { score } } }`)
		Expect(out).To(HaveKey("errors"))
	})

	It("rejects non-POST requests", func() {
		schema, err := graphqladapter.NewSchema(&stubSearcher{}, &stubBlast{})
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

// stubBlast stands in for the blast-radius use case.
type stubBlast struct {
	gotCVE   string
	gotDepth int
	gotLimit int
	result   model.BlastRadius
	err      error
}

func (s *stubBlast) Handle(_ context.Context, cveID string, maxDepth, limit int) (model.BlastRadius, error) {
	s.gotCVE, s.gotDepth, s.gotLimit = cveID, maxDepth, limit
	return s.result, s.err
}

var _ = Describe("GraphQL blastRadius query", func() {
	radius := model.BlastRadius{
		CVEID:              "CVE-2026-64646",
		VulnerablePackages: []string{"npm:next"},
		Repositories: []model.ImpactedRepository{{
			Owner: "vercel", Name: "commerce", URL: "https://github.com/vercel/commerce",
			AuthorName: "vercel", ViaPackage: "npm:next", Depth: 1, Direct: true,
			Path: []string{"vercel/commerce", "npm:next"},
		}},
	}

	run := func(stub *stubBlast, query string) *graphql.Result {
		GinkgoHelper()
		schema, err := graphqladapter.NewSchema(&stubSearcher{}, stub)
		Expect(err).ToNot(HaveOccurred())
		return graphql.Do(graphql.Params{Schema: schema, RequestString: query})
	}

	It("returns the exposed repositories with their dependency chain", func() {
		stub := &stubBlast{result: radius}

		result := run(stub, `{ blastRadius(cveId:"CVE-2026-64646", maxDepth:3, limit:50){
			cveId linked totalRepositories vulnerablePackages
			repositories { fullName owner name url authorName viaPackage depth direct path chain }
		} }`)

		Expect(result.Errors).To(BeEmpty())
		Expect(stub.gotCVE).To(Equal("CVE-2026-64646"))
		Expect(stub.gotDepth).To(Equal(3))
		Expect(stub.gotLimit).To(Equal(50))

		data, ok := result.Data.(map[string]any)
		Expect(ok).To(BeTrue())
		br, ok := data["blastRadius"].(map[string]any)
		Expect(ok).To(BeTrue())
		Expect(br["cveId"]).To(Equal("CVE-2026-64646"))
		Expect(br["linked"]).To(Equal(true))
		Expect(br["totalRepositories"]).To(Equal(1))

		repos, ok := br["repositories"].([]any)
		Expect(ok).To(BeTrue())
		Expect(repos).To(HaveLen(1))
		repo, ok := repos[0].(map[string]any)
		Expect(ok).To(BeTrue())
		Expect(repo["fullName"]).To(Equal("vercel/commerce"))
		Expect(repo["direct"]).To(Equal(true))
		Expect(repo["chain"]).To(Equal("vercel/commerce → npm:next"))
	})

	It("distinguishes an unlinked CVE from one that affects nothing", func() {
		// linked=false means we could not answer; it must not read as
		// "nothing is affected".
		stub := &stubBlast{result: model.BlastRadius{CVEID: "CVE-2021-44228"}}

		result := run(stub, `{ blastRadius(cveId:"CVE-2021-44228"){ linked totalRepositories } }`)

		Expect(result.Errors).To(BeEmpty())
		data, _ := result.Data.(map[string]any)
		br, _ := data["blastRadius"].(map[string]any)
		Expect(br["linked"]).To(Equal(false))
		Expect(br["totalRepositories"]).To(Equal(0))
	})

	It("surfaces a use-case failure as a GraphQL error", func() {
		stub := &stubBlast{err: errors.New("graph unavailable")}

		result := run(stub, `{ blastRadius(cveId:"CVE-1"){ cveId } }`)

		Expect(result.Errors).ToNot(BeEmpty())
		Expect(result.Errors[0].Message).To(ContainSubstring("graph unavailable"))
	})

	It("requires a cveId", func() {
		result := run(&stubBlast{}, `{ blastRadius{ cveId } }`)
		Expect(result.Errors).ToNot(BeEmpty())
	})
})

var _ = Describe("GraphQL search sort and totals", func() {
	run := func(stub *stubSearcher, query string) *graphql.Result {
		GinkgoHelper()
		schema, err := graphqladapter.NewSchema(stub, &stubBlast{})
		Expect(err).ToNot(HaveOccurred())
		return graphql.Do(graphql.Params{Schema: schema, RequestString: query})
	}

	It("serves the live feed: no term, newest first", func() {
		stub := &stubSearcher{result: model.SearchResult{TotalResults: 6771, NextPageToken: "25"}}

		result := run(stub, `{ search(sort: NEWEST, pageSize: 25){ totalResults totalIsLowerBound nextPageToken } }`)

		Expect(result.Errors).To(BeEmpty())
		Expect(stub.gotSort).To(Equal(model.SortNewest))
		Expect(stub.gotTerm).To(BeEmpty())

		data, _ := result.Data.(map[string]any)
		search, _ := data["search"].(map[string]any)
		Expect(search["totalResults"]).To(BeEquivalentTo(6771))
		Expect(search["nextPageToken"]).To(Equal("25"))
	})

	It("defaults to relevance, so existing clients behave as before", func() {
		stub := &stubSearcher{}
		result := run(stub, `{ search(term: "log4j"){ nextPageToken } }`)

		Expect(result.Errors).To(BeEmpty())
		Expect(stub.gotSort).To(Equal(model.SortRelevance))
	})

	It("rejects a sort it does not know", func() {
		result := run(&stubSearcher{}, `{ search(term: "x", sort: SIDEWAYS){ nextPageToken } }`)
		Expect(result.Errors).ToNot(BeEmpty())
	})
})

type stubVulnerability struct{ v model.Vulnerability }

func (s stubVulnerability) Handle(context.Context, string) (model.Vulnerability, error) {
	return s.v, nil
}

type stubWatchlist struct {
	tracked   []string
	untracked string
}

func (s *stubWatchlist) Tracked(context.Context) ([]model.TrackedRepository, error) {
	return []model.TrackedRepository{{FullName: "vercel/next.js", Status: "scanned", DependencyCount: 12}}, nil
}

func (s *stubWatchlist) Discover(_ context.Context, owner string, _ int) ([]model.DiscoveredRepository, error) {
	return []model.DiscoveredRepository{{FullName: owner + "/swr", Stars: 30000, Tracked: true}}, nil
}

func (s *stubWatchlist) Track(_ context.Context, names []string) ([]model.TrackedRepository, error) {
	s.tracked = names
	out := make([]model.TrackedRepository, 0, len(names))
	for _, n := range names {
		out = append(out, model.TrackedRepository{FullName: n, Status: "pending"})
	}
	return out, nil
}

func (s *stubWatchlist) Untrack(_ context.Context, name string) (bool, error) {
	s.untracked = name
	return true, nil
}

var _ = Describe("GraphQL details and watchlist", func() {
	It("serves one finding with its sources and affected version ranges", func() {
		schema, err := graphqladapter.NewSchema(&stubSearcher{}, &stubBlast{},
			graphqladapter.WithVulnerability(stubVulnerability{v: model.Vulnerability{
				CVEID:            "CVE-2025-55182",
				Title:            "React Server Components are Vulnerable to RCE",
				Sources:          []string{"nvd", "package_feed"},
				AffectedPackages: []model.AffectedPackage{{Package: "npm:react-server-dom-webpack", VersionRange: ">= 19.0.0, < 19.0.1"}},
			}}))
		Expect(err).ToNot(HaveOccurred())

		out := post(graphqladapter.NewHandler(schema),
			`{ vulnerability(cveId: "CVE-2025-55182") { title sources affectedPackages { package versionRange } } }`)

		Expect(out).ToNot(HaveKey("errors"))
		v := out["data"].(map[string]any)["vulnerability"].(map[string]any)
		Expect(v["sources"]).To(ConsistOf("nvd", "package_feed"))
		pkg := v["affectedPackages"].([]any)[0].(map[string]any)
		Expect(pkg["versionRange"]).To(Equal(">= 19.0.0, < 19.0.1"))
	})

	It("lists, discovers, tracks and untracks repositories", func() {
		watch := &stubWatchlist{}
		schema, err := graphqladapter.NewSchema(&stubSearcher{}, &stubBlast{}, graphqladapter.WithWatchlist(watch))
		Expect(err).ToNot(HaveOccurred())
		h := graphqladapter.NewHandler(schema)

		out := post(h, `{ trackedRepositories { fullName status dependencyCount } discoverRepositories(owner: "vercel") { fullName tracked stars } }`)
		Expect(out).ToNot(HaveKey("errors"))
		data := out["data"].(map[string]any)
		Expect(data["trackedRepositories"].([]any)[0].(map[string]any)["dependencyCount"]).To(BeEquivalentTo(12))
		Expect(data["discoverRepositories"].([]any)[0].(map[string]any)["tracked"]).To(BeTrue())

		out = post(h, `mutation { trackRepositories(fullNames: ["vercel/swr", "vercel/ai"]) { fullName status } }`)
		Expect(out).ToNot(HaveKey("errors"))
		Expect(watch.tracked).To(Equal([]string{"vercel/swr", "vercel/ai"}))

		out = post(h, `mutation { untrackRepository(fullName: "vercel/swr") }`)
		Expect(out["data"].(map[string]any)["untrackRepository"]).To(BeTrue())
		Expect(watch.untracked).To(Equal("vercel/swr"))
	})

	It("keeps the fields in the schema but reports them unavailable when not wired", func() {
		schema, err := graphqladapter.NewSchema(&stubSearcher{}, &stubBlast{})
		Expect(err).ToNot(HaveOccurred())

		out := post(graphqladapter.NewHandler(schema), `{ trackedRepositories { fullName } }`)
		Expect(out["errors"]).ToNot(BeEmpty())
	})
})
