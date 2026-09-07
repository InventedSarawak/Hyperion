package github_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/github"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/sourcehttp"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

const sample = `[
 {"ghsa_id":"GHSA-jfh8-c2jp-5v3q","cve_id":"CVE-2021-44228",
  "html_url":"https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
  "summary":"Log4Shell","description":"Remote code execution in Log4j",
  "severity":"critical","published_at":"2021-12-10T00:00:00Z","updated_at":"2023-01-01T00:00:00Z",
  "cvss":{"score":10.0,"vector_string":"CVSS:3.1/AV:N/AC:L"},
  "references":["https://example.test/ref"],
  "vulnerabilities":[
    {"package":{"ecosystem":"maven","name":"org.apache.logging.log4j:log4j-core"},
     "vulnerable_version_range":">= 2.0.1, < 2.15.0"},
    {"package":{"ecosystem":"maven","name":"org.apache.logging.log4j:log4j-core"},
     "vulnerable_version_range":">= 2.13.0, < 2.16.0"},
    {"package":{"ecosystem":"pip","name":"nothing"},"vulnerable_version_range":"< 1.0"},
    {"package":{"ecosystem":"npm","name":""},"vulnerable_version_range":"< 1.0"}
  ]},
 {"ghsa_id":"GHSA-only-no-cve","cve_id":null,"summary":"No CVE assigned",
  "description":"desc","severity":"moderate","published_at":"2024-01-01T00:00:00Z",
  "updated_at":"2024-01-02T00:00:00Z","cvss":{"score":0,"vector_string":""},"references":[]}
]`

var _ = Describe("GitHub Advisory adapter", func() {
	ctx := context.Background()

	It("maps advisories, preferring the CVE id", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(sample))
		}))
		defer srv.Close()

		c := github.New(srv.URL, "", sourcehttp.WithHTTPClient(srv.Client()), sourcehttp.WithRateLimit(time.Millisecond))
		Expect(c.Kind()).To(Equal(valueobject.SourceKindGitHubAdvisory))

		got, err := c.Fetch(ctx, time.Time{})
		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(HaveLen(2))

		Expect(got[0].CVEID).To(Equal("CVE-2021-44228"))
		Expect(got[0].Title).To(Equal("Log4Shell"))
		Expect(got[0].Scores).To(HaveLen(1))
		Expect(got[0].Scores[0].BaseScore).To(Equal(10.0))
		Expect(got[0].Scores[0].Severity).To(Equal(model.SeverityCritical))
		Expect(got[0].Scores[0].Version).To(Equal("3.1"))
		Expect(got[0].References).To(ContainElement("https://github.com/advisories/GHSA-jfh8-c2jp-5v3q"))
	})

	It("maps the affected packages that link an advisory into the graph", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(sample))
		}))
		defer srv.Close()

		got, err := github.New(srv.URL, "", sourcehttp.WithHTTPClient(srv.Client()), sourcehttp.WithRateLimit(time.Millisecond)).Fetch(ctx, time.Time{})
		Expect(err).ToNot(HaveOccurred())

		// Two entries for log4j-core collapse to one; "pip" normalizes to
		// pypi; the entry with no package name is dropped.
		Expect(got[0].AffectedPackages).To(HaveLen(2))
		Expect(got[0].AffectedPackages[0].Ecosystem).To(Equal(valueobject.EcosystemMaven))
		Expect(got[0].AffectedPackages[0].Name).To(Equal("org.apache.logging.log4j:log4j-core"))
		Expect(got[0].AffectedPackages[0].Version).To(Equal(">= 2.0.1, < 2.15.0"))
		Expect(got[0].AffectedPackages[1].Ecosystem).To(Equal(valueobject.EcosystemPyPI))
	})

	It("leaves affected packages nil when the advisory names none", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(sample))
		}))
		defer srv.Close()

		got, err := github.New(srv.URL, "", sourcehttp.WithHTTPClient(srv.Client()), sourcehttp.WithRateLimit(time.Millisecond)).Fetch(ctx, time.Time{})
		Expect(err).ToNot(HaveOccurred())
		Expect(got[1].AffectedPackages).To(BeNil())
	})

	It("falls back to the GHSA id when no CVE is assigned", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(sample))
		}))
		defer srv.Close()

		got, err := github.New(srv.URL, "", sourcehttp.WithHTTPClient(srv.Client()), sourcehttp.WithRateLimit(time.Millisecond)).Fetch(ctx, time.Time{})
		Expect(err).ToNot(HaveOccurred())
		Expect(got[1].CVEID).To(Equal("GHSA-only-no-cve"))
	})

	It("sends the bearer token and the modified filter", func() {
		var gotAuth, gotQuery string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotAuth, gotQuery = r.Header.Get("Authorization"), r.URL.RawQuery
			_, _ = w.Write([]byte(`[]`))
		}))
		defer srv.Close()

		_, err := github.New(srv.URL, "tok123", sourcehttp.WithHTTPClient(srv.Client()), sourcehttp.WithRateLimit(time.Millisecond)).
			Fetch(ctx, time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC))

		Expect(err).ToNot(HaveOccurred())
		Expect(gotAuth).To(Equal("Bearer tok123"))
		Expect(gotQuery).To(ContainSubstring("modified"))
		Expect(gotQuery).To(ContainSubstring("per_page=100"))
	})
})

var _ = Describe("GitHub Advisory reviewed pass", func() {
	ctx := context.Background()

	// The unfiltered feed is almost entirely "unreviewed" NVD imports with no
	// package data; the reviewed feed is where the package linkage lives.
	const unreviewed = `[{"ghsa_id":"GHSA-unreviewed","cve_id":"CVE-2026-0001",
	  "summary":"Imported from NVD","severity":"high","vulnerabilities":[]}]`
	const reviewed = `[{"ghsa_id":"GHSA-reviewed","cve_id":"CVE-2026-0002",
	  "summary":"Curated","severity":"critical",
	  "vulnerabilities":[{"package":{"ecosystem":"npm","name":"lodash"},
	    "vulnerable_version_range":"< 4.17.21"}]}]`

	It("asks for reviewed advisories explicitly, so package linkage is not crowded out", func() {
		var types []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			advisoryType := r.URL.Query().Get("type")
			types = append(types, advisoryType)
			if advisoryType == "reviewed" {
				_, _ = w.Write([]byte(reviewed))
				return
			}
			_, _ = w.Write([]byte(unreviewed))
		}))
		defer srv.Close()

		got, err := github.New(srv.URL, "", sourcehttp.WithHTTPClient(srv.Client()),
			sourcehttp.WithRateLimit(time.Millisecond)).Fetch(ctx, time.Time{})

		Expect(err).ToNot(HaveOccurred())
		Expect(types).To(ContainElement("reviewed"))
		Expect(types).To(ContainElement(""), "the unfiltered feed is still read")

		Expect(got).To(HaveLen(2))
		Expect(got[0].AffectedPackages).To(BeEmpty())
		Expect(got[1].CVEID).To(Equal("CVE-2026-0002"))
		Expect(got[1].AffectedPackages).To(HaveLen(1))
		Expect(got[1].AffectedPackages[0].Name).To(Equal("lodash"))
	})

	It("does not report an advisory twice when it appears in both passes", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(reviewed))
		}))
		defer srv.Close()

		got, err := github.New(srv.URL, "", sourcehttp.WithHTTPClient(srv.Client()),
			sourcehttp.WithRateLimit(time.Millisecond)).Fetch(ctx, time.Time{})

		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(HaveLen(1))
	})
})
