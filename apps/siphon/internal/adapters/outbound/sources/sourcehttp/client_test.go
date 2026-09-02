package sourcehttp_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/sourcehttp"
)

var _ = Describe("sourcehttp client", func() {
	ctx := context.Background()
	fast := time.Millisecond

	It("decodes JSON responses", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"name":"hyperion"}`))
		}))
		defer srv.Close()

		var out struct {
			Name string `json:"name"`
		}
		err := sourcehttp.New(fast, sourcehttp.WithHTTPClient(srv.Client())).GetJSON(ctx, srv.URL, &out)

		Expect(err).ToNot(HaveOccurred())
		Expect(out.Name).To(Equal("hyperion"))
	})

	It("sends configured headers", func() {
		var got string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = r.Header.Get("Authorization")
			_, _ = w.Write([]byte(`{}`))
		}))
		defer srv.Close()

		c := sourcehttp.New(fast,
			sourcehttp.WithHTTPClient(srv.Client()),
			sourcehttp.WithHeader("Authorization", "Bearer xyz"))
		_, err := c.GetBytes(ctx, srv.URL)

		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(Equal("Bearer xyz"))
	})

	It("retries a transient 500 then succeeds", func() {
		var calls int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if atomic.AddInt32(&calls, 1) == 1 {
				http.Error(w, "boom", http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		defer srv.Close()

		_, err := sourcehttp.New(fast, sourcehttp.WithHTTPClient(srv.Client())).GetBytes(ctx, srv.URL)

		Expect(err).ToNot(HaveOccurred())
		Expect(atomic.LoadInt32(&calls)).To(Equal(int32(2)))
	})

	It("does NOT retry once the request budget is exhausted", func() {
		var calls int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			atomic.AddInt32(&calls, 1)
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", fmt.Sprint(time.Now().Add(time.Hour).Unix()))
			http.Error(w, "API rate limit exceeded", http.StatusForbidden)
		}))
		defer srv.Close()

		_, err := sourcehttp.New(fast, sourcehttp.WithHTTPClient(srv.Client())).GetBytes(ctx, srv.URL)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("rate limit exhausted"))
		Expect(atomic.LoadInt32(&calls)).To(Equal(int32(1))) // failed fast, no retries
	})

	It("still retries a 403 that is not a budget exhaustion", func() {
		var calls int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if atomic.AddInt32(&calls, 1) < 2 {
				http.Error(w, "temporarily forbidden", http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(`{}`))
		}))
		defer srv.Close()

		_, err := sourcehttp.New(fast, sourcehttp.WithHTTPClient(srv.Client())).GetBytes(ctx, srv.URL)

		Expect(err).ToNot(HaveOccurred())
		Expect(atomic.LoadInt32(&calls)).To(Equal(int32(2)))
	})

	It("does not retry a non-retryable status", func() {
		var calls int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			atomic.AddInt32(&calls, 1)
			http.Error(w, "bad", http.StatusBadRequest)
		}))
		defer srv.Close()

		_, err := sourcehttp.New(fast, sourcehttp.WithHTTPClient(srv.Client())).GetBytes(ctx, srv.URL)

		Expect(err).To(HaveOccurred())
		Expect(atomic.LoadInt32(&calls)).To(Equal(int32(1)))
	})
})
