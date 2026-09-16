package github_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/github"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
)

var _ = Describe("GitHub repository catalog", func() {
	ctx := context.Background()

	It("falls back from /orgs to /users and maps the listing", func() {
		var paths []string
		var auth string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			paths = append(paths, r.URL.Path)
			auth = r.Header.Get("Authorization")
			if strings.HasPrefix(r.URL.Path, "/orgs/") {
				http.NotFound(w, r)
				return
			}
			Expect(r.URL.Query().Get("type")).To(Equal("owner"))
			_, _ = w.Write([]byte(`[
			  {"full_name":"torvalds/linux","description":"Linux kernel source tree","language":"C",
			   "stargazers_count":190000,"pushed_at":"2026-09-10T10:00:00Z","fork":false,"archived":false},
			  {"full_name":"torvalds/old","archived":true,"fork":true},
			  {"full_name":"torvalds/disabled","disabled":true}
			]`))
		}))
		defer srv.Close()

		got, err := github.New(srv.Client(), srv.URL, "tok").ListOwnerRepositories(ctx, "@torvalds", 50)

		Expect(err).ToNot(HaveOccurred())
		Expect(paths).To(Equal([]string{"/orgs/torvalds/repos", "/users/torvalds/repos"}))
		Expect(auth).To(Equal("Bearer tok"))
		Expect(got).To(HaveLen(2), "a disabled repository cannot be read, so it is not offered")
		Expect(got[0].FullName).To(Equal("torvalds/linux"))
		Expect(got[0].Stars).To(Equal(190000))
		Expect(got[0].PushedAt.Year()).To(Equal(2026))
		Expect(got[1].Fork).To(BeTrue())
		Expect(got[1].Archived).To(BeTrue())
	})

	It("reports an owner that is neither an org nor a user as not found", func() {
		srv := httptest.NewServer(http.NotFoundHandler())
		defer srv.Close()

		_, err := github.New(srv.Client(), srv.URL, "").ListOwnerRepositories(ctx, "no-such-owner", 10)
		Expect(err).To(MatchError(ports.ErrOwnerNotFound))
	})

	It("pages until the limit and stops there", func() {
		var pages int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			pages++
			var items []string
			for i := 0; i < 100; i++ {
				items = append(items, fmt.Sprintf(`{"full_name":"big/r%d-%d"}`, pages, i))
			}
			_, _ = w.Write([]byte("[" + strings.Join(items, ",") + "]"))
		}))
		defer srv.Close()

		got, err := github.New(srv.Client(), srv.URL, "").ListOwnerRepositories(ctx, "big", 150)
		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(HaveLen(150))
		Expect(pages).To(Equal(2))
	})

	It("says how to fix an exhausted rate limit", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()

		_, err := github.New(srv.Client(), srv.URL, "").ListOwnerRepositories(ctx, "vercel", 10)
		Expect(err).To(MatchError(ContainSubstring("CORTEX_GITHUB_TOKEN")))
	})
})
