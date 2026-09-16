package scheduler_test

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/inbound/scheduler"
)

// pollerFunc adapts a function to the scheduler.Poller interface.
type pollerFunc func(context.Context) (int, error)

func (f pollerFunc) Run(ctx context.Context) (int, error) { return f(ctx) }

var _ = Describe("Scheduler", func() {
	It("polls immediately on start and returns when the context is cancelled", func() {
		var calls int32
		poller := pollerFunc(func(context.Context) (int, error) {
			atomic.AddInt32(&calls, 1)
			return 0, nil
		})

		s := scheduler.New(poller, time.Hour) // long interval; only the immediate poll fires
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- s.Start(ctx) }()

		Eventually(func() int32 { return atomic.LoadInt32(&calls) }).Should(BeNumerically(">=", 1))
		cancel()
		Eventually(done).Should(Receive(MatchError(context.Canceled)))
	})

	It("keeps ticking after a poll fails", func() {
		var calls int32
		poller := pollerFunc(func(context.Context) (int, error) {
			atomic.AddInt32(&calls, 1)
			return 0, errors.New("every source is down")
		})

		s := scheduler.New(poller, 20*time.Millisecond)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- s.Start(ctx) }()

		// A failing source must not stop the timer: the next tick is the
		// retry, and whatever the poller uses to track its position was left
		// untouched by the run that failed.
		Eventually(func() int32 { return atomic.LoadInt32(&calls) }, "5s").Should(BeNumerically(">=", 3))
		cancel()
		Eventually(done, "5s").Should(Receive(MatchError(context.Canceled)))
	})
})
