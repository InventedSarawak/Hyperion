package health_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/packages/common/health"
)

func ok(context.Context) error   { return nil }
func down(context.Context) error { return errors.New("connection refused") }

var _ = Describe("Health checks", func() {
	ctx := context.Background()

	It("is healthy when every check answers", func() {
		report := health.New(time.Second,
			health.Check{Name: "postgres", Required: true, Probe: ok},
			health.Check{Name: "elasticsearch", Probe: ok},
		).Run(ctx)

		Expect(report.Healthy).To(BeTrue())
		Expect(report.Degraded()).To(BeFalse())
		Expect(report.Failing()).To(BeEmpty())
	})

	It("is unhealthy when a required check fails", func() {
		report := health.New(time.Second,
			health.Check{Name: "postgres", Required: true, Probe: down},
		).Run(ctx)

		Expect(report.Healthy).To(BeFalse())
		Expect(report.Failing()).To(Equal([]string{"postgres"}))
		Expect(report.Checks[0].Error).To(ContainSubstring("connection refused"))
	})

	It("stays healthy but degraded when an optional check fails", func() {
		// cortex keeps ingesting with Elasticsearch down, on purpose. A probe
		// that failed on it would have an orchestrator restart a service
		// doing its most important job correctly.
		report := health.New(time.Second,
			health.Check{Name: "postgres", Required: true, Probe: ok},
			health.Check{Name: "elasticsearch", Probe: down},
		).Run(ctx)

		Expect(report.Healthy).To(BeTrue())
		Expect(report.Degraded()).To(BeTrue())
		Expect(report.Failing()).To(Equal([]string{"elasticsearch"}))
	})

	It("names required failures before optional ones", func() {
		report := health.New(time.Second,
			health.Check{Name: "elasticsearch", Probe: down},
			health.Check{Name: "postgres", Required: true, Probe: down},
		).Run(ctx)

		Expect(report.Failing()).To(Equal([]string{"postgres", "elasticsearch"}))
	})

	It("counts a probe that will not answer as failed", func() {
		// A dependency too slow to answer is one the service cannot use, and
		// a health endpoint that blocks is worse than one that says no.
		start := time.Now()
		report := health.New(50*time.Millisecond,
			health.Check{Name: "slow", Required: true, Probe: func(ctx context.Context) error {
				<-ctx.Done()
				return ctx.Err()
			}},
		).Run(ctx)

		Expect(report.Healthy).To(BeFalse())
		Expect(time.Since(start)).To(BeNumerically("<", time.Second))
	})

	It("asks every dependency at once, not one after another", func() {
		slow := func(context.Context) error { time.Sleep(80 * time.Millisecond); return nil }
		start := time.Now()
		health.New(time.Second,
			health.Check{Name: "a", Probe: slow},
			health.Check{Name: "b", Probe: slow},
			health.Check{Name: "c", Probe: slow},
		).Run(ctx)

		Expect(time.Since(start)).To(BeNumerically("<", 200*time.Millisecond))
	})

	It("is healthy with nothing to check", func() {
		Expect(health.New(time.Second).Run(ctx).Healthy).To(BeTrue())
	})
})

var _ = Describe("Health over HTTP", func() {
	serve := func(checks ...health.Check) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		health.Handler(health.New(time.Second, checks...)).
			ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		return rec
	}

	It("answers 200 with the report when healthy", func() {
		rec := serve(health.Check{Name: "cortex", Required: true, Probe: ok})
		Expect(rec.Code).To(Equal(http.StatusOK))

		var report health.Report
		Expect(json.Unmarshal(rec.Body.Bytes(), &report)).To(Succeed())
		Expect(report.Healthy).To(BeTrue())
		Expect(report.Checks).To(HaveLen(1))
	})

	It("answers 503 and still says which dependency is down", func() {
		// The status code is for the prober; the body is for whoever has to
		// work out what happened.
		rec := serve(health.Check{Name: "cortex", Required: true, Probe: down})
		Expect(rec.Code).To(Equal(http.StatusServiceUnavailable))
		Expect(rec.Body.String()).To(ContainSubstring("connection refused"))
	})

	It("forbids caching, since a stale health answer is a wrong one", func() {
		Expect(serve().Header().Get("Cache-Control")).To(Equal("no-store"))
	})
})
