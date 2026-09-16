package graphql_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	graphqladapter "github.com/inventedsarawak/hyperion/apps/deck/internal/adapters/outbound/graphql"
	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// sseServer writes the given raw SSE body and holds the connection until the
// client leaves.
func sseServer(body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, body)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
}

var _ = Describe("live feed over SSE", func() {
	It("delivers each finding the gateway sends", func() {
		srv := sseServer(
			"event: finding\ndata: {\"id\":\"CVE-2021-44228\",\"title\":\"Log4Shell\",\"kind\":\"vulnerability\",\"severity\":\"CRITICAL\",\"score\":10,\"sources\":[\"nvd\"]}\n\n" +
				"event: finding\ndata: {\"id\":\"GHSA-xxxx\",\"kind\":\"malware\"}\n\n")
		defer srv.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		updates, err := graphqladapter.New(srv.URL+"/graphql", srv.Client()).StreamFindings(ctx)
		Expect(err).NotTo(HaveOccurred())

		var first model.Vulnerability
		Eventually(updates, "5s").Should(Receive(&first))
		Expect(first.CVEID).To(Equal("CVE-2021-44228"))
		Expect(first.Title).To(Equal("Log4Shell"))
		Expect(first.Scores).To(HaveLen(1))
		Expect(first.Scores[0].BaseScore).To(Equal(float64(10)))
		Expect(first.Scores[0].Severity).To(Equal("CRITICAL"))

		var second model.Vulnerability
		Eventually(updates, "5s").Should(Receive(&second))
		Expect(second.CVEID).To(Equal("GHSA-xxxx"))
		Expect(second.Kind).To(Equal(model.FindingKind("malware")))
	})

	It("ignores keep-alive comments, which arrive whenever the feed is quiet", func() {
		srv := sseServer(": keep-alive\n\n: keep-alive\n\nevent: finding\ndata: {\"id\":\"CVE-2024-1\"}\n\n")
		defer srv.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		updates, err := graphqladapter.New(srv.URL+"/graphql", srv.Client()).StreamFindings(ctx)
		Expect(err).NotTo(HaveOccurred())

		var v model.Vulnerability
		Eventually(updates, "5s").Should(Receive(&v))
		Expect(v.CVEID).To(Equal("CVE-2024-1"))
	})

	It("closes the channel when the gateway says the feed ended", func() {
		srv := sseServer("event: end\ndata: {}\n\n")
		defer srv.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		updates, err := graphqladapter.New(srv.URL+"/graphql", srv.Client()).StreamFindings(ctx)
		Expect(err).NotTo(HaveOccurred())

		// A closed channel is how a reader is told the feed is over, rather
		// than waiting forever on one that will never speak again.
		Eventually(updates, "5s").Should(BeClosed())
	})

	It("skips an event whose payload will not parse, and keeps reading", func() {
		srv := sseServer("event: finding\ndata: {not json}\n\nevent: finding\ndata: {\"id\":\"CVE-2024-2\"}\n\n")
		defer srv.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		updates, err := graphqladapter.New(srv.URL+"/graphql", srv.Client()).StreamFindings(ctx)
		Expect(err).NotTo(HaveOccurred())

		var v model.Vulnerability
		Eventually(updates, "5s").Should(Receive(&v))
		Expect(v.CVEID).To(Equal("CVE-2024-2"))
	})

	It("reports a gateway that refuses the connection, so deck can fall back to polling", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "no feed here", http.StatusServiceUnavailable)
		}))
		defer srv.Close()

		_, err := graphqladapter.New(srv.URL+"/graphql", srv.Client()).
			StreamFindings(context.Background())

		Expect(err).To(MatchError(ContainSubstring("503")))
	})

	It("stops when the caller cancels", func() {
		srv := sseServer("event: finding\ndata: {\"id\":\"CVE-2024-3\"}\n\n")
		defer srv.Close()

		ctx, cancel := context.WithCancel(context.Background())
		updates, err := graphqladapter.New(srv.URL+"/graphql", srv.Client()).StreamFindings(ctx)
		Expect(err).NotTo(HaveOccurred())

		Eventually(updates, "5s").Should(Receive())
		cancel()
		Eventually(updates, "5s").Should(BeClosed())
	})
})
