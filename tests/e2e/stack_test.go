// Package e2e drives a running Hyperion the way a client does: cortex over
// gRPC and nexus over GraphQL, using nothing but the published contracts. It
// is deliberately outside every service — Go's internal rule means a shared
// module cannot reach into them, and a black-box suite should not want to. It
// tests the binaries that are actually deployed, against whatever data they
// hold.
//
//	task up && task test:e2e
package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	commonv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/common/v1"
	intelv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/intelligence/v1"
	watchlistv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/watchlist/v1"
)

// graphql posts a query to nexus and returns the data, failing on any error
// the gateway reports.
func graphql(endpoint, query string, variables map[string]any) map[string]any {
	GinkgoHelper()
	body, err := json.Marshal(map[string]any{"query": query, "variables": variables})
	Expect(err).ToNot(HaveOccurred())

	resp, err := http.Post(endpoint, "application/json", bytes.NewReader(body))
	Expect(err).ToNot(HaveOccurred())
	defer resp.Body.Close()
	Expect(resp.StatusCode).To(Equal(http.StatusOK))

	var envelope struct {
		Data   map[string]any `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	Expect(json.NewDecoder(resp.Body).Decode(&envelope)).To(Succeed())
	Expect(envelope.Errors).To(BeEmpty())
	return envelope.Data
}

var _ = Describe("A running Hyperion", func() {
	var (
		ctx      = context.Background()
		intel    intelv1.IntelligenceServiceClient
		watch    watchlistv1.WatchlistServiceClient
		graphAPI string
	)

	BeforeEach(func() {
		addr, gateway := os.Getenv("HYPERION_E2E_CORTEX_ADDR"), os.Getenv("HYPERION_E2E_NEXUS_URL")
		if addr == "" || gateway == "" {
			Skip("set HYPERION_E2E_CORTEX_ADDR and HYPERION_E2E_NEXUS_URL against a running stack (task up)")
		}
		graphAPI = gateway

		conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(func() { Expect(conn.Close()).To(Succeed()) })
		intel = intelv1.NewIntelligenceServiceClient(conn)
		watch = watchlistv1.NewWatchlistServiceClient(conn)
	})

	It("serves the newest findings, and each one again by every id it carries", func() {
		deadline, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		feed, err := intel.Search(deadline, &intelv1.SearchRequest{
			Sort: intelv1.SearchSort_SEARCH_SORT_NEWEST, PageSize: 5,
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(feed.GetResults()).ToNot(BeEmpty(), "an empty store has nothing to test; run task backfill first")

		for _, result := range feed.GetResults() {
			v := result.GetVulnerability()
			Expect(v.GetCveId()).ToNot(BeEmpty())

			for _, id := range append([]string{v.GetCveId()}, v.GetAliases()...) {
				got, err := intel.GetVulnerability(deadline, &intelv1.GetVulnerabilityRequest{CveId: id})
				Expect(err).ToNot(HaveOccurred(), id)
				Expect(got.GetVulnerability().GetCveId()).To(Equal(v.GetCveId()),
					"every id resolves to the finding's canonical one")
			}
		}
	})

	It("keeps malware out of an ordinary search, and finds it when asked", func() {
		deadline, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		malware, err := intel.Search(deadline, &intelv1.SearchRequest{
			Query: "malicious code", PageSize: 5,
			Kinds: []commonv1.FindingKind{commonv1.FindingKind_FINDING_KIND_MALWARE},
		})
		Expect(err).ToNot(HaveOccurred())
		for _, r := range malware.GetResults() {
			Expect(r.GetVulnerability().GetKind()).To(Equal(commonv1.FindingKind_FINDING_KIND_MALWARE))
		}

		ordinary, err := intel.Search(deadline, &intelv1.SearchRequest{
			Query: "malicious code", PageSize: 5,
			Kinds: []commonv1.FindingKind{commonv1.FindingKind_FINDING_KIND_VULNERABILITY},
		})
		Expect(err).ToNot(HaveOccurred())
		for _, r := range ordinary.GetResults() {
			Expect(r.GetVulnerability().GetKind()).ToNot(Equal(commonv1.FindingKind_FINDING_KIND_MALWARE))
		}
	})

	It("answers what a tracked repository is exposed to, and judges it by version", func() {
		deadline, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		tracked, err := watch.ListRepositories(deadline, &watchlistv1.ListRepositoriesRequest{})
		Expect(err).ToNot(HaveOccurred())
		if len(tracked.GetRepositories()) == 0 {
			Skip("no repositories tracked; add one in deck's Repositories tab")
		}

		var scanned *watchlistv1.TrackedRepository
		for _, r := range tracked.GetRepositories() {
			if r.GetDependencyCount() > 0 {
				scanned = r
				break
			}
		}
		if scanned == nil {
			Skip("no repository has been scanned yet")
		}

		exposure, err := intel.GetRepositoryExposure(deadline, &intelv1.GetRepositoryExposureRequest{
			FullName: scanned.GetFullName(), IncludeUnaffected: true,
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(exposure.GetScanned()).To(BeTrue())

		for _, f := range exposure.GetFindings() {
			Expect(f.GetVerdict()).ToNot(Equal(commonv1.ExposureVerdict_EXPOSURE_VERDICT_UNSPECIFIED),
				"every finding is judged, one way or another")
			Expect(f.GetViaPackage().GetName()).ToNot(BeEmpty())

			// A finding that is reported as exposure must reach this
			// repository from the other direction too.
			if f.GetVerdict() == commonv1.ExposureVerdict_EXPOSURE_VERDICT_AFFECTED {
				radius, err := intel.GetBlastRadius(deadline, &intelv1.GetBlastRadiusRequest{
					CveId: f.GetVulnerability().GetCveId(), MaxDepth: 3, Limit: 100,
				})
				Expect(err).ToNot(HaveOccurred())
				names := []string{}
				for _, r := range radius.GetRepositories() {
					names = append(names, r.GetRepository().GetOwner()+"/"+r.GetRepository().GetName())
				}
				Expect(names).To(ContainElement(scanned.GetFullName()))
				break // one round trip is enough to prove the two agree
			}
		}
	})

	It("serves the same answers through the gateway", func() {
		data := graphql(graphAPI, `{ trackedRepositories { fullName status dependencyCount
			exposure { computed criticalAffected highAffected total } } }`, nil)
		repos, ok := data["trackedRepositories"].([]any)
		Expect(ok).To(BeTrue())
		if len(repos) == 0 {
			Skip("no repositories tracked")
		}

		first := repos[0].(map[string]any)
		Expect(first["fullName"]).ToNot(BeEmpty())

		exposure := graphql(graphAPI, `query($n: String!){ repositoryExposure(fullName: $n) {
			fullName scanned summary { computed total }
			findings { verdict package declaredVersion vulnerability { cveId kind } } } }`,
			map[string]any{"n": first["fullName"]})
		got := exposure["repositoryExposure"].(map[string]any)
		Expect(got["fullName"]).To(Equal(first["fullName"]))

		for _, f := range got["findings"].([]any) {
			finding := f.(map[string]any)
			Expect(finding["verdict"]).To(BeElementOf("AFFECTED", "POSSIBLY_AFFECTED", "UNKNOWN"),
				"what a repository is exposed to excludes what its versions rule out")
		}
	})
})
