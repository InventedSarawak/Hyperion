package scheduler_test

import (
	"context"
	"errors"
	"sync"
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

// fakeCheckpoints is a stand-in CheckpointStore (outbound port): it remembers
// what was saved, and can be told to fail either half.
type fakeCheckpoints struct {
	mu       sync.Mutex
	stored   map[string]time.Time
	loadErr  error
	saveErr  error
	loads    int
	saves    int
	lastSave time.Time
}

func newFakeCheckpoints() *fakeCheckpoints {
	return &fakeCheckpoints{stored: map[string]time.Time{}}
}

func (f *fakeCheckpoints) Load(_ context.Context, name string) (time.Time, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loads++
	if f.loadErr != nil {
		return time.Time{}, false, f.loadErr
	}
	at, ok := f.stored[name]
	return at, ok, nil
}

func (f *fakeCheckpoints) Save(_ context.Context, name string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.saves++
	if f.saveErr != nil {
		return f.saveErr
	}
	f.stored[name] = at
	f.lastSave = at
	return nil
}

func (f *fakeCheckpoints) saveCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.saves
}

func (f *fakeCheckpoints) saved() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastSave
}

// runOnce starts a scheduler with an interval long enough that only the
// immediate poll fires, waits for that poll, and stops it.
func runOnce(s *scheduler.Scheduler, polled <-chan time.Time) time.Time {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()

	var since time.Time
	Eventually(polled, "5s").Should(Receive(&since))
	cancel()
	Eventually(done, "5s").Should(Receive(MatchError(context.Canceled)))
	return since
}

var _ = Describe("Scheduler watermark", func() {
	var (
		store  *fakeCheckpoints
		polled chan time.Time
		poller scheduler.Poller
	)

	BeforeEach(func() {
		store = newFakeCheckpoints()
		polled = make(chan time.Time, 4)
		poller = pollerFunc(func(_ context.Context, since time.Time) (int, error) {
			polled <- since
			return 1, nil
		})
	})

	It("starts from the stored watermark rather than the lookback window", func() {
		// Down for a day, with a two-hour lookback: everything between must
		// still be read, which is only possible if the watermark survived.
		stored := time.Now().Add(-24 * time.Hour).UTC().Truncate(time.Second)
		Expect(store.Save(context.Background(), "advisories", stored)).To(Succeed())

		s := scheduler.New(poller, time.Hour, 2*time.Hour).WithCheckpoint(store, "advisories")

		Expect(runOnce(s, polled)).To(BeTemporally("==", stored))
	})

	It("falls back to the lookback window when nothing is stored yet", func() {
		s := scheduler.New(poller, time.Hour, 2*time.Hour).WithCheckpoint(store, "advisories")

		since := runOnce(s, polled)
		Expect(since).To(BeTemporally("~", time.Now().Add(-2*time.Hour), time.Minute))
	})

	It("falls back to the lookback window when the store cannot be read, rather than refusing to poll", func() {
		store.loadErr = errors.New("redis is down")
		s := scheduler.New(poller, time.Hour, 2*time.Hour).WithCheckpoint(store, "advisories")

		since := runOnce(s, polled)
		Expect(since).To(BeTemporally("~", time.Now().Add(-2*time.Hour), time.Minute))
	})

	It("records the watermark after a successful poll", func() {
		s := scheduler.New(poller, time.Hour, 2*time.Hour).WithCheckpoint(store, "advisories")
		runOnce(s, polled)

		Eventually(store.saveCount, "5s").Should(BeNumerically(">=", 1))
		Expect(store.saved()).To(BeTemporally("~", time.Now(), time.Minute))
	})

	It("does not record a watermark for a poll that failed", func() {
		failing := pollerFunc(func(_ context.Context, since time.Time) (int, error) {
			polled <- since
			return 0, errors.New("every source is down")
		})
		s := scheduler.New(failing, time.Hour, 2*time.Hour).WithCheckpoint(store, "advisories")
		runOnce(s, polled)

		// Advancing past a window that was never read is exactly how signals
		// go missing, so a failed poll must leave the bookmark alone.
		Consistently(store.saveCount, "1s").Should(BeZero())
	})

	It("keeps polling when the watermark cannot be saved", func() {
		store.saveErr = errors.New("redis went away")
		s := scheduler.New(poller, 50*time.Millisecond, 2*time.Hour).WithCheckpoint(store, "advisories")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- s.Start(ctx) }()

		// The events were published either way; losing the bookmark only costs
		// a re-read on the next start.
		Eventually(func() int { return len(polled) }, "5s").Should(BeNumerically(">=", 2))
		cancel()
		Eventually(done, "5s").Should(Receive(MatchError(context.Canceled)))
	})
})
