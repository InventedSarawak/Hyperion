package graphql_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	gatewayadapter "github.com/inventedsarawak/hyperion/apps/deck/internal/adapters/outbound/graphql"
	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// gateway serves a canned GraphQL response and captures the request.
func gateway(body string, status int, captured *map[string]any) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if captured != nil {
			_ = json.NewDecoder(r.Body).Decode(captured)
		}
		w.Header().Set("Content-Type", "application/json")
		if status != 0 {
			w.WriteHeader(status)
		}
		_, _ = w.Write([]byte(body))
	}))
}

var _ = Describe("Gateway client", func() {
	ctx := context.Background()

	Describe("Search", func() {
		It("maps the gateway response into view models", func() {
			var req map[string]any
			srv := gateway(`{"data":{"search":{"hits":[
			  {"score":8.5,"vulnerability":{
			    "cveId":"CVE-2021-44228","title":"Log4Shell","description":"JNDI",
			    "references":["https://example.test/a"],
			    "publishedAt":"2021-12-10T00:00:00Z",
			    "scores":[{"version":"3.1","baseScore":10,"vector":"CVSS:3.1/AV:N","severity":"CRITICAL"}]}}
			]}}}`, 0, &req)
			defer srv.Close()

			page, err := gatewayadapter.New(srv.URL, srv.Client()).Search(ctx, "log4j", model.SortRelevance, 25, "")
			hits := page.Hits

			Expect(err).ToNot(HaveOccurred())
			Expect(hits).To(HaveLen(1))
			Expect(hits[0].Score).To(Equal(8.5))

			v := hits[0].Vulnerability
			Expect(v.CVEID).To(Equal("CVE-2021-44228"))
			Expect(v.SeverityLabel()).To(Equal("CRITICAL"))
			Expect(v.PublishedAt.Year()).To(Equal(2021))
			Expect(v.References).To(ContainElement("https://example.test/a"))

			// The query is parameterised, not string-concatenated.
			vars, ok := req["variables"].(map[string]any)
			Expect(ok).To(BeTrue())
			Expect(vars["term"]).To(Equal("log4j"))
			Expect(vars["pageSize"]).To(BeEquivalentTo(25))
		})

		It("returns no hits without erroring when the feed is empty", func() {
			srv := gateway(`{"data":{"search":{"hits":[]}}}`, 0, nil)
			defer srv.Close()

			page, err := gatewayadapter.New(srv.URL, srv.Client()).Search(ctx, "nothing", model.SortRelevance, 25, "")
			hits := page.Hits

			Expect(err).ToNot(HaveOccurred())
			Expect(hits).To(BeEmpty())
		})
	})

	Describe("BlastRadius", func() {
		It("maps the traversal into view models", func() {
			srv := gateway(`{"data":{"blastRadius":{
			  "cveId":"CVE-2026-64646","linked":true,"vulnerablePackages":["npm:next"],
			  "repositories":[{"fullName":"vercel/commerce","authorName":"vercel",
			    "url":"https://github.com/vercel/commerce","viaPackage":"npm:next",
			    "depth":1,"direct":true,"path":["vercel/commerce","npm:next"]}]}}}`, 0, nil)
			defer srv.Close()

			radius, err := gatewayadapter.New(srv.URL, srv.Client()).BlastRadius(ctx, "CVE-2026-64646", 3)

			Expect(err).ToNot(HaveOccurred())
			Expect(radius.CVEID).To(Equal("CVE-2026-64646"))
			Expect(radius.Linked()).To(BeTrue())
			Expect(radius.Repositories).To(HaveLen(1))
			Expect(radius.Repositories[0].FullName).To(Equal("vercel/commerce"))
			Expect(radius.Repositories[0].Chain()).To(Equal("vercel/commerce → npm:next"))
			Expect(radius.Repositories[0].Reach()).To(Equal("direct"))
		})

		It("reports an unlinked CVE as unanswered rather than unaffected", func() {
			srv := gateway(`{"data":{"blastRadius":{"cveId":"CVE-1","linked":false,
			  "vulnerablePackages":[],"repositories":[]}}}`, 0, nil)
			defer srv.Close()

			radius, err := gatewayadapter.New(srv.URL, srv.Client()).BlastRadius(ctx, "CVE-1", 3)

			Expect(err).ToNot(HaveOccurred())
			Expect(radius.Linked()).To(BeFalse())
		})
	})

	Describe("failures", func() {
		It("surfaces GraphQL errors, which arrive inside a 200 response", func() {
			// A GraphQL failure is not an HTTP failure; trusting the status
			// code alone would make an error look like an empty result.
			srv := gateway(`{"errors":[{"message":"graph unavailable"}]}`, 0, nil)
			defer srv.Close()

			_, err := gatewayadapter.New(srv.URL, srv.Client()).Search(ctx, "log4j", model.SortRelevance, 25, "")

			Expect(err).To(MatchError(ContainSubstring("graph unavailable")))
		})

		It("reports a non-200 response with the body", func() {
			srv := gateway(`gateway is down`, http.StatusBadGateway, nil)
			defer srv.Close()

			_, err := gatewayadapter.New(srv.URL, srv.Client()).Search(ctx, "log4j", model.SortRelevance, 25, "")

			Expect(err).To(MatchError(ContainSubstring("502")))
			Expect(err).To(MatchError(ContainSubstring("gateway is down")))
		})

		It("reports a response carrying neither data nor errors", func() {
			srv := gateway(`{}`, 0, nil)
			defer srv.Close()

			_, err := gatewayadapter.New(srv.URL, srv.Client()).Search(ctx, "log4j", model.SortRelevance, 25, "")

			Expect(err).To(MatchError(ContainSubstring("no data")))
		})

		It("reports an unreachable gateway", func() {
			srv := gateway(`{}`, 0, nil)
			srv.Close() // closed on purpose

			_, err := gatewayadapter.New(srv.URL, srv.Client()).Search(ctx, "log4j", model.SortRelevance, 25, "")

			Expect(err).To(HaveOccurred())
		})
	})
})

var _ = Describe("Gateway client paging", func() {
	ctx := context.Background()

	It("sends the sort and page token, and reads back the next token and total", func() {
		var req map[string]any
		srv := gateway(`{"data":{"search":{"nextPageToken":"50","totalResults":6771,
		  "totalIsLowerBound":false,"hits":[]}}}`, 0, &req)
		defer srv.Close()

		page, err := gatewayadapter.New(srv.URL, srv.Client()).Search(ctx, "", model.SortNewest, 25, "25")

		Expect(err).ToNot(HaveOccurred())
		Expect(page.NextPageToken).To(Equal("50"))
		Expect(page.Total).To(Equal(int64(6771)))

		vars, _ := req["variables"].(map[string]any)
		Expect(vars["sort"]).To(Equal("NEWEST"))
		Expect(vars["pageToken"]).To(Equal("25"))
		Expect(vars["term"]).To(Equal(""))
	})

	It("asks for best match when sorting by relevance", func() {
		var req map[string]any
		srv := gateway(`{"data":{"search":{"hits":[]}}}`, 0, &req)
		defer srv.Close()

		_, err := gatewayadapter.New(srv.URL, srv.Client()).Search(ctx, "next", model.SortRelevance, 25, "")

		Expect(err).ToNot(HaveOccurred())
		vars, _ := req["variables"].(map[string]any)
		Expect(vars["sort"]).To(Equal("RELEVANCE"))
	})
})
