package scheduler_test

import (
	"context"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/inbound/scheduler"
)

// pollerFunc adapts a function to the scheduler.Poller interface.
type pollerFunc func(context.Context, time.Time) (int, error)

func (f pollerFunc) Run(ctx context.Context, since time.Time) (int, error) { return f(ctx, since) }

var _ = Describe("Scheduler", func() {
	It("polls immediately on start and returns when the context is cancelled", func() {
		var calls int32
		poller := pollerFunc(func(context.Context, time.Time) (int, error) {
			atomic.AddInt32(&calls, 1)
			return 0, nil
		})

		s := scheduler.New(poller, time.Hour, time.Minute) // long interval; only the immediate poll fires
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- s.Start(ctx) }()

		Eventually(func() int32 { return atomic.LoadInt32(&calls) }).Should(BeNumerically(">=", 1))
		cancel()
		Eventually(done).Should(Receive(MatchError(context.Canceled)))
	})
})
