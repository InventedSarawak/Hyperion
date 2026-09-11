package nvd_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/nvd"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// fast keeps the real rate limiter out of the way in tests.
var fast = nvd.WithRequestDelay(time.Millisecond)

// a trimmed but realistic NVD API 2.0 response.
const sampleResponse = `{
  "resultsPerPage": 1,
  "totalResults": 1,
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2021-44228",
        "published": "2021-12-10T10:15:09.143",
        "lastModified": "2023-04-03T20:15:08.960",
        "descriptions": [
          {"lang": "es", "value": "descripcion"},
          {"lang": "en", "value": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP."}
        ],
        "metrics": {
          "cvssMetricV31": [
            {"cvssData": {"version": "3.1", "baseScore": 10.0, "vectorString": "CVSS:3.1/AV:N", "baseSeverity": "CRITICAL"}}
          ]
        },
        "references": [
          {"url": "https://logging.apache.org/log4j/"},
          {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}
        ]
      }
    }
  ]
}`

var _ = Describe("NVD Client", func() {
	ctx := context.Background()

	It("maps an NVD response into domain SourceSignals", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(sampleResponse))
		}))
		defer srv.Close()

		client := nvd.New(srv.Client(), srv.URL, "", fast)
		Expect(client.Kind()).To(Equal(valueobject.SourceKindNVD))

		signals, err := client.Fetch(ctx, time.Time{})
		Expect(err).ToNot(HaveOccurred())
		Expect(signals).To(HaveLen(1))

		s := signals[0]
		Expect(s.CVEID).To(Equal("CVE-2021-44228"))
		Expect(s.Description).To(ContainSubstring("Apache Log4j2")) // english picked over spanish
		Expect(s.References).To(HaveLen(2))
		Expect(s.Scores).To(HaveLen(1))
		Expect(s.Scores[0].BaseScore).To(Equal(10.0))
		Expect(s.Scores[0].Severity).To(Equal(model.SeverityCritical))
		Expect(s.PublishedAt.Year()).To(Equal(2021))
	})

	It("returns an error on a non-retryable status", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "bad request", http.StatusBadRequest)
		}))
		defer srv.Close()

		_, err := nvd.New(srv.Client(), srv.URL, "", fast).Fetch(ctx, time.Time{})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unexpected status 400"))
	})

	It("sends the incremental date filter when since is set", func() {
		var gotQuery string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotQuery = r.URL.RawQuery
			_, _ = w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
		}))
		defer srv.Close()

		since := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
		_, err := nvd.New(srv.Client(), srv.URL, "", fast).Fetch(ctx, since)
		Expect(err).ToNot(HaveOccurred())
		Expect(gotQuery).To(ContainSubstring("lastModStartDate"))
		Expect(gotQuery).To(ContainSubstring("lastModEndDate"))
	})

	It("clamps the request window to NVD's 120-day maximum", func() {
		var gotStart string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotStart = r.URL.Query().Get("lastModStartDate")
			_, _ = w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
		}))
		defer srv.Close()

		// Ask for two years back; the adapter must not request beyond 120 days.
		_, err := nvd.New(srv.Client(), srv.URL, "", fast).Fetch(ctx, time.Now().Add(-2*365*24*time.Hour))
		Expect(err).ToNot(HaveOccurred())

		parsed, perr := time.Parse("2006-01-02T15:04:05.000", gotStart)
		Expect(perr).ToNot(HaveOccurred())
		Expect(time.Since(parsed)).To(BeNumerically("<=", 121*24*time.Hour))
	})

	It("walks pagination until the result set is drained", func() {
		var calls int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&calls, 1)
			startIndex := r.URL.Query().Get("startIndex")
			id := "CVE-PAGE-1"
			if startIndex == "2" {
				id = "CVE-PAGE-2"
			}
			// totalResults=4 with pageSize=2 -> exactly two pages.
			fmt.Fprintf(w, `{"totalResults":4,"vulnerabilities":[{"cve":{"id":%q}},{"cve":{"id":"%s-b"}}]}`, id, id)
		}))
		defer srv.Close()

		client := nvd.New(srv.Client(), srv.URL, "", fast, nvd.WithPageSize(2))
		signals, err := client.Fetch(ctx, time.Time{})

		Expect(err).ToNot(HaveOccurred())
		Expect(atomic.LoadInt32(&calls)).To(Equal(int32(2)))
		Expect(signals).To(HaveLen(4))
		Expect(signals[0].CVEID).To(Equal("CVE-PAGE-1"))
		Expect(signals[2].CVEID).To(Equal("CVE-PAGE-2"))
	})

	It("leaves the title empty, because NVD has none", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(sampleResponse))
		}))
		defer srv.Close()

		signals, err := nvd.New(srv.Client(), srv.URL, "", fast).Fetch(ctx, time.Time{})
		Expect(err).ToNot(HaveOccurred())
		// A placeholder title (the id) would overwrite real titles from
		// other feeds on merge, and hide the description in every list.
		Expect(signals[0].Title).To(BeEmpty())
	})

	Describe("Backfill", func() {
		It("walks consecutive published-date windows of at most 120 days up to now", func() {
			var (
				mu      sync.Mutex
				windows [][2]time.Time
			)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				start, _ := time.Parse("2006-01-02T15:04:05.000", r.URL.Query().Get("pubStartDate"))
				end, _ := time.Parse("2006-01-02T15:04:05.000", r.URL.Query().Get("pubEndDate"))
				defer GinkgoRecover()
				Expect(r.URL.Query().Get("lastModStartDate")).To(BeEmpty())
				mu.Lock()
				windows = append(windows, [2]time.Time{start, end})
				mu.Unlock()
				_, _ = w.Write([]byte(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2020-0001"}}]}`))
			}))
			defer srv.Close()

			from := time.Now().Add(-365 * 24 * time.Hour)
			var emitted int
			err := nvd.New(srv.Client(), srv.URL, "", fast).Backfill(ctx, from, func(page []model.SourceSignal) error {
				emitted += len(page)
				return nil
			})

			Expect(err).ToNot(HaveOccurred())
			// Windows are fetched concurrently, so check coverage in date order.
			sort.Slice(windows, func(i, j int) bool { return windows[i][0].Before(windows[j][0]) })
			Expect(windows).To(HaveLen(4)) // 365 days = three full windows and a remainder
			for i, w := range windows {
				Expect(w[1].Sub(w[0])).To(BeNumerically("<=", 120*24*time.Hour))
				if i > 0 {
					Expect(w[0]).To(BeTemporally("==", windows[i-1][1]), "windows must not leave a gap")
				}
			}
			Expect(time.Since(windows[len(windows)-1][1])).To(BeNumerically("<", time.Minute))
			Expect(emitted).To(Equal(4))
		})

		It("ignores the max-pages bound, so history is not silently truncated", func() {
			var calls int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				atomic.AddInt32(&calls, 1)
				_, _ = w.Write([]byte(`{"totalResults":5,"vulnerabilities":[{"cve":{"id":"CVE-X"}}]}`))
			}))
			defer srv.Close()

			client := nvd.New(srv.Client(), srv.URL, "", fast, nvd.WithPageSize(1), nvd.WithMaxPages(2))
			err := client.Backfill(ctx, time.Now().Add(-24*time.Hour), func([]model.SourceSignal) error { return nil })

			Expect(err).ToNot(HaveOccurred())
			Expect(atomic.LoadInt32(&calls)).To(Equal(int32(5)))
		})

		It("retries a page whose body breaks off mid-read", func() {
			var calls int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if atomic.AddInt32(&calls, 1) == 1 {
					// Promise more than is sent, then hang up: the client
					// sees a truncated body, as with a connection reset.
					w.Header().Set("Content-Length", "100000")
					_, _ = w.Write([]byte(`{"totalResults":1,"vulnerabilities":[{"cve":`))
					return
				}
				_, _ = w.Write([]byte(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2025-55182"}}]}`))
			}))
			defer srv.Close()

			var got []string
			err := nvd.New(srv.Client(), srv.URL, "", fast).Backfill(ctx, time.Now().Add(-24*time.Hour),
				func(page []model.SourceSignal) error {
					for _, s := range page {
						got = append(got, s.CVEID)
					}
					return nil
				})
			Expect(err).ToNot(HaveOccurred())
			Expect(got).To(Equal([]string{"CVE-2025-55182"}))
			Expect(atomic.LoadInt32(&calls)).To(Equal(int32(2)))
		})

		It("keeps reading other windows when one cannot be served, and names the hole", func() {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				start, _ := time.Parse("2006-01-02T15:04:05.000", r.URL.Query().Get("pubStartDate"))
				if time.Since(start) > 200*24*time.Hour {
					http.Error(w, "bad window", http.StatusBadRequest) // not retryable
					return
				}
				_, _ = w.Write([]byte(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-X"}}]}`))
			}))
			defer srv.Close()

			var emitted int
			var mu sync.Mutex
			err := nvd.New(srv.Client(), srv.URL, "", fast).Backfill(ctx, time.Now().Add(-365*24*time.Hour),
				func(page []model.SourceSignal) error {
					mu.Lock()
					emitted += len(page)
					mu.Unlock()
					return nil
				})

			Expect(err).To(MatchError(ContainSubstring("window(s) incomplete")))
			Expect(emitted).To(Equal(2), "the two recent windows are still read")
		})

		It("stops at the first failed emit", func() {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-X"}}]}`))
			}))
			defer srv.Close()

			boom := fmt.Errorf("pipe closed")
			err := nvd.New(srv.Client(), srv.URL, "", fast).Backfill(ctx, time.Now().Add(-365*24*time.Hour),
				func([]model.SourceSignal) error { return boom })
			Expect(err).To(MatchError(boom))
		})
	})

	It("honours the max-pages bound", func() {
		var calls int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			atomic.AddInt32(&calls, 1)
			_, _ = w.Write([]byte(`{"totalResults":1000,"vulnerabilities":[{"cve":{"id":"CVE-X"}}]}`))
		}))
		defer srv.Close()

		client := nvd.New(srv.Client(), srv.URL, "", fast, nvd.WithPageSize(1), nvd.WithMaxPages(3))
		_, err := client.Fetch(ctx, time.Time{})

		Expect(err).ToNot(HaveOccurred())
		Expect(atomic.LoadInt32(&calls)).To(Equal(int32(3)))
	})

	It("retries a throttled 429 and then succeeds", func() {
		var calls int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if atomic.AddInt32(&calls, 1) == 1 {
				http.Error(w, "rate limited", http.StatusTooManyRequests)
				return
			}
			_, _ = w.Write([]byte(sampleResponse))
		}))
		defer srv.Close()

		signals, err := nvd.New(srv.Client(), srv.URL, "", fast).Fetch(ctx, time.Time{})

		Expect(err).ToNot(HaveOccurred())
		Expect(atomic.LoadInt32(&calls)).To(Equal(int32(2)))
		Expect(signals).To(HaveLen(1))
	})

	It("sends the apiKey header when a key is configured", func() {
		var gotKey string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotKey = r.Header.Get("apiKey")
			_, _ = w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
		}))
		defer srv.Close()

		_, err := nvd.New(srv.Client(), srv.URL, "secret-key", fast).Fetch(ctx, time.Time{})
		Expect(err).ToNot(HaveOccurred())
		Expect(gotKey).To(Equal("secret-key"))
	})
})
