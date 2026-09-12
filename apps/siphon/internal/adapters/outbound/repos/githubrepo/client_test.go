package githubrepo_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/repos/githubrepo"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/sourcehttp"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

const repoMeta = `{
  "name":"gin","html_url":"https://github.com/gin-gonic/gin","default_branch":"master",
  "owner":{"login":"gin-gonic","html_url":"https://github.com/gin-gonic"}
}`

const goMod = `module github.com/gin-gonic/gin

go 1.23

require golang.org/x/net v0.17.0

require golang.org/x/sys v0.13.0 // indirect
`

// contentsResponse renders a file the way the contents API does: base64,
// wrapped at 60 columns.
func contentsResponse(body string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(body))
	var wrapped strings.Builder
	for i := 0; i < len(encoded); i += 60 {
		end := i + 60
		if end > len(encoded) {
			end = len(encoded)
		}
		wrapped.WriteString(encoded[i:end] + "\n")
	}
	payload, err := json.Marshal(map[string]any{
		"content": wrapped.String(), "encoding": "base64", "size": len(body),
	})
	Expect(err).ToNot(HaveOccurred())
	return string(payload)
}

// server routes the endpoints the adapter calls. Any path not in files 404s.
// Unless a test serves one, a repository's tree lists exactly the files it
// serves through the contents API.
func server(files map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := files[r.URL.Path]; ok {
			_, _ = w.Write([]byte(body))
			return
		}
		if m := treePath.FindStringSubmatch(r.URL.Path); m != nil {
			if _, known := files["/repos/"+m[1]]; known {
				prefix := "/repos/" + m[1] + "/contents/"
				var paths []string
				for p := range files {
					if strings.HasPrefix(p, prefix) {
						paths = append(paths, strings.TrimPrefix(p, prefix))
					}
				}
				_, _ = w.Write([]byte(treeResponse(paths...)))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	}))
}

var treePath = regexp.MustCompile(`^/repos/([^/]+/[^/]+)/git/trees/[^/]+$`)

// treeResponse renders a recursive tree listing of plain files.
func treeResponse(paths ...string) string {
	entries := make([]map[string]string, 0, len(paths))
	for _, p := range paths {
		entries = append(entries, map[string]string{"path": p, "type": "blob", "sha": "0"})
	}
	payload, err := json.Marshal(map[string]any{"tree": entries, "truncated": false})
	Expect(err).ToNot(HaveOccurred())
	return string(payload)
}

func byName(deps []model.Dependency, name string) model.Dependency {
	GinkgoHelper()
	for _, d := range deps {
		if d.Package.Name == name {
			return d
		}
	}
	Fail("no dependency named " + name)
	return model.Dependency{}
}

var _ = Describe("GitHub repository adapter", func() {
	ctx := context.Background()

	It("reads a go.mod into a repository snapshot", func() {
		srv := server(map[string]string{
			"/repos/gin-gonic/gin":                 repoMeta,
			"/repos/gin-gonic/gin/contents/go.mod": contentsResponse(goMod),
		})
		defer srv.Close()

		got, err := githubrepo.New(srv.URL, "", sourcehttp.WithHTTPClient(srv.Client()), sourcehttp.WithRateLimit(time.Millisecond)).
			Scan(ctx, "gin-gonic", "gin")

		Expect(err).ToNot(HaveOccurred())
		Expect(got.Repository.FullName()).To(Equal("gin-gonic/gin"))
		Expect(got.Repository.DefaultBranch).To(Equal("master"))
		Expect(got.Repository.URL).To(Equal("https://github.com/gin-gonic/gin"))
		Expect(got.Author.Login).To(Equal("gin-gonic"))
		Expect(got.Publishes.Name).To(Equal("github.com/gin-gonic/gin"))
		Expect(got.Publishes.Ecosystem).To(Equal(valueobject.EcosystemGo))
		Expect(got.Dependencies).To(HaveLen(2))
		Expect(byName(got.Dependencies, "golang.org/x/net").Direct).To(BeTrue())
		Expect(byName(got.Dependencies, "golang.org/x/sys").Direct).To(BeFalse())
		Expect(got.ObservedAt.IsZero()).To(BeFalse())
	})

	It("merges every manifest a repository declares", func() {
		srv := server(map[string]string{
			"/repos/acme/app":                       repoMeta,
			"/repos/acme/app/contents/go.mod":       contentsResponse(goMod),
			"/repos/acme/app/contents/package.json": contentsResponse(`{"name":"ui","dependencies":{"react":"18.2.0"}}`),
		})
		defer srv.Close()

		got, err := githubrepo.New(srv.URL, "", sourcehttp.WithHTTPClient(srv.Client()), sourcehttp.WithRateLimit(time.Millisecond)).
			Scan(ctx, "acme", "app")

		Expect(err).ToNot(HaveOccurred())
		Expect(got.Dependencies).To(HaveLen(3))
		Expect(byName(got.Dependencies, "react").Package.Ecosystem).To(Equal(valueobject.EcosystemNPM))
		// go.mod is tried first, so its module line is the one kept.
		Expect(got.Publishes.Name).To(Equal("github.com/gin-gonic/gin"))
	})

	It("treats a missing manifest as an absence, not a failure", func() {
		srv := server(map[string]string{"/repos/acme/docs": repoMeta})
		defer srv.Close()

		got, err := githubrepo.New(srv.URL, "", sourcehttp.WithHTTPClient(srv.Client()), sourcehttp.WithRateLimit(time.Millisecond)).
			Scan(ctx, "acme", "docs")

		Expect(err).ToNot(HaveOccurred())
		Expect(got.Dependencies).To(BeEmpty())
		Expect(got.Repository.FullName()).ToNot(BeEmpty(), "the repository is still worth recording")
	})

	It("reports a manifest that is present but unreadable", func() {
		srv := server(map[string]string{
			"/repos/acme/app":                       repoMeta,
			"/repos/acme/app/contents/package.json": contentsResponse(`{"name":`),
		})
		defer srv.Close()

		got, err := githubrepo.New(srv.URL, "", sourcehttp.WithHTTPClient(srv.Client()), sourcehttp.WithRateLimit(time.Millisecond)).
			Scan(ctx, "acme", "app")

		Expect(err).To(HaveOccurred(), "a broken manifest is a coverage gap, not an absence")
		Expect(got.Repository.FullName()).ToNot(BeEmpty())
	})

	It("fails when the repository itself cannot be read", func() {
		srv := server(nil)
		defer srv.Close()

		_, err := githubrepo.New(srv.URL, "", sourcehttp.WithHTTPClient(srv.Client()), sourcehttp.WithRateLimit(time.Millisecond)).
			Scan(ctx, "acme", "missing")

		Expect(err).To(MatchError(sourcehttp.ErrNotFound))
		// This is what the Repositories tab shows beside the failed scan.
		Expect(err.Error()).To(HavePrefix("GitHub has no repository acme/missing"))
		Expect(err.Error()).ToNot(ContainSubstring("https://"))
	})

	It("falls back to the requested identity when the API omits it", func() {
		srv := server(map[string]string{"/repos/acme/app": `{"default_branch":"main","owner":{}}`})
		defer srv.Close()

		got, err := githubrepo.New(srv.URL, "", sourcehttp.WithHTTPClient(srv.Client()), sourcehttp.WithRateLimit(time.Millisecond)).
			Scan(ctx, "acme", "app")

		Expect(err).ToNot(HaveOccurred())
		Expect(got.Repository.FullName()).To(Equal("acme/app"))
	})

	It("skips a file too large for the API to inline", func() {
		srv := server(map[string]string{
			"/repos/acme/app":                 repoMeta,
			"/repos/acme/app/contents/go.mod": `{"content":"","encoding":"none","size":2000000}`,
		})
		defer srv.Close()

		_, err := githubrepo.New(srv.URL, "", sourcehttp.WithHTTPClient(srv.Client()), sourcehttp.WithRateLimit(time.Millisecond)).
			Scan(ctx, "acme", "app")

		Expect(err).To(MatchError(ContainSubstring("no inline content")))
	})

	It("sends the bearer token when one is configured", func() {
		var gotAuth string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			switch r.URL.Path {
			case "/repos/acme/app":
				_, _ = w.Write([]byte(repoMeta))
				return
			case "/repos/acme/app/git/trees/master":
				_, _ = w.Write([]byte(treeResponse()))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		_, err := githubrepo.New(srv.URL, "ghp_secret", sourcehttp.WithHTTPClient(srv.Client()), sourcehttp.WithRateLimit(time.Millisecond)).
			Scan(ctx, "acme", "app")

		Expect(err).ToNot(HaveOccurred())
		Expect(gotAuth).To(Equal("Bearer ghp_secret"))
	})
})

var _ = Describe("GitHub repository discovery", func() {
	ctx := context.Background()

	const orgRepos = `[
	  {"full_name":"vercel/next.js","name":"next.js","fork":false,"archived":false,"owner":{"login":"vercel"}},
	  {"full_name":"vercel/commerce","name":"commerce","fork":false,"archived":false,"owner":{"login":"vercel"}},
	  {"full_name":"vercel/a-fork","name":"a-fork","fork":true,"owner":{"login":"vercel"}},
	  {"full_name":"vercel/old","name":"old","archived":true,"owner":{"login":"vercel"}},
	  {"full_name":"vercel/off","name":"off","disabled":true,"owner":{"login":"vercel"}}
	]`

	newClient := func(srv *httptest.Server) *githubrepo.Client {
		return githubrepo.New(srv.URL, "", sourcehttp.WithHTTPClient(srv.Client()),
			sourcehttp.WithRateLimit(time.Millisecond))
	}

	It("lists an organization's repositories, skipping forks and archived ones", func() {
		srv := server(map[string]string{"/orgs/vercel/repos": orgRepos})
		defer srv.Close()

		got, err := newClient(srv).Discover(ctx, "vercel", 20)

		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(Equal([]string{"vercel/next.js", "vercel/commerce"}))
	})

	It("falls back to the user endpoint when the owner is not an organization", func() {
		// GitHub 404s /orgs for a personal account, so the caller should not
		// have to know which kind of owner they typed.
		srv := server(map[string]string{
			"/users/torvalds/repos": `[{"full_name":"torvalds/linux","name":"linux","owner":{"login":"torvalds"}}]`,
		})
		defer srv.Close()

		got, err := newClient(srv).Discover(ctx, "torvalds", 20)

		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(Equal([]string{"torvalds/linux"}))
	})

	It("honours the per-owner limit", func() {
		srv := server(map[string]string{"/orgs/vercel/repos": orgRepos})
		defer srv.Close()

		got, err := newClient(srv).Discover(ctx, "vercel", 1)

		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(HaveLen(1))
	})

	It("sorts by recent activity so a limit keeps the repositories that matter", func() {
		var gotQuery string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotQuery = r.URL.RawQuery
			_, _ = w.Write([]byte(orgRepos))
		}))
		defer srv.Close()

		_, err := newClient(srv).Discover(ctx, "vercel", 20)

		Expect(err).ToNot(HaveOccurred())
		Expect(gotQuery).To(ContainSubstring("sort=pushed"))
		Expect(gotQuery).To(ContainSubstring("direction=desc"))
	})

	It("reports an owner that exists as neither an organization nor a user", func() {
		srv := server(nil)
		defer srv.Close()

		_, err := newClient(srv).Discover(ctx, "nobody", 20)

		Expect(err).To(HaveOccurred())
	})

	It("rejects an empty owner", func() {
		srv := server(nil)
		defer srv.Close()

		_, err := newClient(srv).Discover(ctx, "", 20)

		Expect(err).To(MatchError(ContainSubstring("owner is required")))
	})
})

var _ = Describe("GitHub repository adapter across languages", func() {
	ctx := context.Background()
	client := func(srv *httptest.Server) *githubrepo.Client {
		return githubrepo.New(srv.URL, "", sourcehttp.WithHTTPClient(srv.Client()), sourcehttp.WithRateLimit(time.Millisecond))
	}

	It("reads dependency files wherever a monorepo keeps them, and not installed packages", func() {
		srv := server(map[string]string{
			"/repos/acme/mono":                                         repoMeta,
			"/repos/acme/mono/contents/apps/api/go.mod":                contentsResponse(goMod),
			"/repos/acme/mono/contents/apps/web/package.json":          contentsResponse(`{"name":"web","private":true,"dependencies":{"react":"18.2.0"}}`),
			"/repos/acme/mono/contents/backend/requirements.txt":       contentsResponse("fastapi==0.109.2\n"),
			"/repos/acme/mono/contents/node_modules/evil/package.json": contentsResponse(`{"name":"evil","dependencies":{"not-ours":"1.0.0"}}`),
		})
		defer srv.Close()

		got, err := client(srv).Scan(ctx, "acme", "mono")

		Expect(err).ToNot(HaveOccurred())
		Expect(byName(got.Dependencies, "golang.org/x/net").ManifestPath).To(Equal("apps/api/go.mod"))
		Expect(byName(got.Dependencies, "react").ManifestPath).To(Equal("apps/web/package.json"))
		Expect(byName(got.Dependencies, "fastapi").Package.Ecosystem).To(Equal(valueobject.EcosystemPyPI))
		for _, d := range got.Dependencies {
			Expect(d.Package.Name).ToNot(Equal("not-ours"), "node_modules is someone else's code")
		}
	})

	It("treats a repository with no commits as nothing to read, not a failure", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/repos/acme/empty":
				_, _ = w.Write([]byte(repoMeta))
			case "/repos/acme/empty/git/trees/master":
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"message":"Git Repository is empty."}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		got, err := client(srv).Scan(ctx, "acme", "empty")

		Expect(err).ToNot(HaveOccurred())
		Expect(got.Dependencies).To(BeEmpty())
		Expect(got.Repository.FullName()).ToNot(BeEmpty())
	})

	It("reads the version of a Solidity library vendored as a git submodule, at its pinned commit", func() {
		const tree = `{"truncated":false,"tree":[
		  {"path":".gitmodules","type":"blob","sha":"1"},
		  {"path":"contracts/src/Ledger.sol","type":"blob","sha":"2"},
		  {"path":"contracts/lib/forge-std","type":"commit","sha":"7117c90"},
		  {"path":"contracts/lib/openzeppelin-contracts","type":"commit","sha":"fcbae53"}]}`
		files := map[string]string{
			"/repos/acme/ledger":                  repoMeta,
			"/repos/acme/ledger/git/trees/master": tree,
			"/repos/acme/ledger/contents/.gitmodules": contentsResponse(`[submodule "contracts/lib/forge-std"]
	path = contracts/lib/forge-std
	url = https://github.com/foundry-rs/forge-std
[submodule "contracts/lib/openzeppelin-contracts"]
	path = contracts/lib/openzeppelin-contracts
	url = https://github.com/OpenZeppelin/openzeppelin-contracts
`),
			"/repos/OpenZeppelin/openzeppelin-contracts/contents/contracts/package.json": contentsResponse(`{"name":"@openzeppelin/contracts","version":"5.5.0"}`),
			"/repos/foundry-rs/forge-std/contents/package.json":                          contentsResponse(`{"name":"forge-std","version":"1.9.4"}`),
		}
		refs := map[string]string{}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			refs[r.URL.Path] = r.URL.Query().Get("ref")
			if body, ok := files[r.URL.Path]; ok {
				_, _ = w.Write([]byte(body))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		got, err := client(srv).Scan(ctx, "acme", "ledger")

		Expect(err).ToNot(HaveOccurred())
		oz := byName(got.Dependencies, "@openzeppelin/contracts")
		Expect(oz.Package.Ecosystem).To(Equal(valueobject.EcosystemNPM))
		Expect(oz.Package.Version).To(Equal("5.5.0"))
		Expect(oz.Direct).To(BeTrue())
		Expect(oz.ManifestPath).To(Equal(".gitmodules (contracts/lib/openzeppelin-contracts)"))
		Expect(refs["/repos/OpenZeppelin/openzeppelin-contracts/contents/contracts/package.json"]).To(Equal("fcbae53"),
			"the version at the pinned commit, not the library's latest")
	})
})
