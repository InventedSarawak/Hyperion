// Package e2e drives siphon end to end: a repository on GitHub, through the
// scanner and the manifest parsers, over real gRPC to cortex, as the snapshot
// cortex will store. Everything but GitHub and cortex is the production path;
// those two are stood up locally, so the suite needs no network and no
// databases.
package e2e_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"

	commonv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/common/v1"
	intelv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/intelligence/v1"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/intelligence"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/repos/githubrepo"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/sourcehttp"
)

// recordingCortex is cortex's half of the contract: it accepts a manifest read
// and remembers what arrived.
type recordingCortex struct {
	intelv1.UnimplementedIntelligenceServiceServer
	mu   sync.Mutex
	last *intelv1.IngestDependenciesRequest
}

func (c *recordingCortex) IngestDependencies(_ context.Context, req *intelv1.IngestDependenciesRequest) (*intelv1.IngestDependenciesResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.last = req
	return &intelv1.IngestDependenciesResponse{DependenciesWritten: int32(len(req.GetDependencies()))}, nil
}

func (c *recordingCortex) received() *intelv1.IngestDependenciesRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

// contents renders a file the way GitHub's contents API does.
func contents(body string) string {
	GinkgoHelper()
	payload, err := json.Marshal(map[string]any{
		"content": base64.StdEncoding.EncodeToString([]byte(body)), "encoding": "base64", "size": len(body),
	})
	Expect(err).ToNot(HaveOccurred())
	return string(payload)
}

var _ = Describe("A repository scan, end to end", func() {
	ctx := context.Background()

	const tree = `{"truncated":false,"tree":[
	  {"path":"package.json","type":"blob","sha":"1"},
	  {"path":"pnpm-lock.yaml","type":"blob","sha":"2"},
	  {"path":"apps/api/go.mod","type":"blob","sha":"3"},
	  {"path":"backend/requirements.txt","type":"blob","sha":"4"},
	  {"path":".gitmodules","type":"blob","sha":"5"},
	  {"path":"node_modules/evil/package.json","type":"blob","sha":"6"},
	  {"path":"contracts/lib/openzeppelin-contracts","type":"commit","sha":"fcbae53"}]}`

	files := map[string]string{
		"/repos/acme/ledger": `{"name":"ledger","html_url":"https://github.com/acme/ledger",
		  "default_branch":"main","owner":{"login":"acme","html_url":"https://github.com/acme"}}`,
		"/repos/acme/ledger/git/trees/main": tree,
		"/repos/acme/ledger/contents/package.json": contents(
			`{"name":"ledger","private":true,"dependencies":{"axios":"^1.13.2"},"devDependencies":{"turbo":"^2.7.1"}}`),
		"/repos/acme/ledger/contents/pnpm-lock.yaml": contents(`lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      axios:
        specifier: ^1.13.2
        version: 1.13.2
    devDependencies:
      turbo:
        specifier: ^2.7.1
        version: 2.7.1

packages:

  follow-redirects@1.15.6:
    resolution: {integrity: sha512-aaa}
`),
		"/repos/acme/ledger/contents/apps/api/go.mod":          contents("module github.com/acme/ledger/apps/api\n\ngo 1.22\n\nrequire google.golang.org/grpc v1.60.0\n"),
		"/repos/acme/ledger/contents/backend/requirements.txt": contents("fastapi==0.109.2\n"),
		"/repos/acme/ledger/contents/.gitmodules": contents(`[submodule "contracts/lib/openzeppelin-contracts"]
	path = contracts/lib/openzeppelin-contracts
	url = https://github.com/OpenZeppelin/openzeppelin-contracts
`),
		"/repos/OpenZeppelin/openzeppelin-contracts/contents/contracts/package.json": contents(
			`{"name":"@openzeppelin/contracts","version":"5.5.0"}`),
		"/repos/acme/ledger/contents/node_modules/evil/package.json": contents(
			`{"name":"evil","dependencies":{"not-ours":"1.0.0"}}`),
	}

	It("reads every language in the repository and delivers it to cortex", func() {
		github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if body, ok := files[r.URL.Path]; ok {
				_, _ = w.Write([]byte(body))
				return
			}
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
		}))
		defer github.Close()

		cortex := &recordingCortex{}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).ToNot(HaveOccurred())
		server := grpc.NewServer()
		intelv1.RegisterIntelligenceServiceServer(server, cortex)
		go func() { _ = server.Serve(listener) }()
		defer server.Stop()

		By("scanning the repository")
		snapshot, err := githubrepo.New(github.URL, "",
			sourcehttp.WithHTTPClient(github.Client()), sourcehttp.WithRateLimit(time.Millisecond)).
			Scan(ctx, "acme", "ledger")
		Expect(err).ToNot(HaveOccurred())
		Expect(snapshot.Repository.FullName()).To(Equal("acme/ledger"))

		By("publishing it to cortex over gRPC")
		client, err := intelligence.Dial(listener.Addr().String())
		Expect(err).ToNot(HaveOccurred())
		defer client.Close()

		written, err := client.Publish(ctx, snapshot)
		Expect(err).ToNot(HaveOccurred())
		Expect(written).To(BeNumerically(">", 0))

		By("checking what cortex was told")
		req := cortex.received()
		Expect(req).ToNot(BeNil())
		Expect(req.GetRepository().GetOwner()).To(Equal("acme"))

		byName := map[string][]*commonv1.Dependency{}
		for _, d := range req.GetDependencies() {
			name := d.GetPackage().GetName()
			byName[name] = append(byName[name], d)
		}

		// Both readings of axios are sent: the range package.json allows and
		// the version the lockfile installs. cortex keeps the locked one —
		// siphon reports what each file says and does not choose between them.
		Expect(byName).To(HaveKey("axios"))
		versions := map[string]bool{}
		locked := map[string]bool{}
		for _, d := range byName["axios"] {
			versions[d.GetPackage().GetVersion()] = true
			locked[d.GetPackage().GetVersion()] = d.GetLocked()
			Expect(d.GetPackage().GetEcosystem()).To(Equal(commonv1.Ecosystem_ECOSYSTEM_NPM))
		}
		Expect(versions).To(HaveKey("1.13.2"), "the version the lockfile installs")
		Expect(locked["1.13.2"]).To(BeTrue())
		Expect(versions).To(HaveKey("^1.13.2"), "the range the manifest allows")
		Expect(locked["^1.13.2"]).To(BeFalse())

		Expect(byName).To(HaveKey("follow-redirects"), "a transitive package the lockfile resolved")
		Expect(byName["follow-redirects"][0].GetDirect()).To(BeFalse())

		Expect(byName).To(HaveKey("google.golang.org/grpc"))
		Expect(byName["google.golang.org/grpc"][0].GetPackage().GetEcosystem()).To(Equal(commonv1.Ecosystem_ECOSYSTEM_GO))
		Expect(byName["google.golang.org/grpc"][0].GetManifestPath()).To(Equal("apps/api/go.mod"))

		Expect(byName).To(HaveKey("fastapi"))
		Expect(byName["fastapi"][0].GetPackage().GetEcosystem()).To(Equal(commonv1.Ecosystem_ECOSYSTEM_PYPI))

		Expect(byName).To(HaveKey("@openzeppelin/contracts"), "a Solidity library vendored as a submodule")
		Expect(byName["@openzeppelin/contracts"][0].GetPackage().GetVersion()).To(Equal("5.5.0"))

		for name := range byName {
			Expect(name).ToNot(Equal("not-ours"), "node_modules is not the repository's own code")
		}

		By("naming the file every dependency came from")
		for name, entries := range byName {
			for _, d := range entries {
				Expect(strings.TrimSpace(d.GetManifestPath())).ToNot(BeEmpty(), name)
			}
		}
	})
})
