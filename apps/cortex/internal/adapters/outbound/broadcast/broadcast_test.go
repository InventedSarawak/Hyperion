package broadcast_test

import (
	"context"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/outbound/broadcast"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
)

func TestBroadcast(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Cortex Broadcast Suite")
}

var _ = Describe("Broadcaster", func() {
	var ctx = context.Background()

	It("delivers a finding to every current subscriber", func() {
		b := broadcast.New(4)
		first, stopFirst := b.Subscribe()
		defer stopFirst()
		second, stopSecond := b.Subscribe()
		defer stopSecond()

		b.Notify(ctx, model.Vulnerability{CVEID: "CVE-2021-44228"})

		Eventually(first).Should(Receive(Equal(model.Vulnerability{CVEID: "CVE-2021-44228"})))
		Eventually(second).Should(Receive(Equal(model.Vulnerability{CVEID: "CVE-2021-44228"})))
	})

	It("does not block ingest when a subscriber has stopped reading", func() {
		b := broadcast.New(2)
		_, stop := b.Subscribe()
		defer stop()

		// Far more than the buffer holds, from a subscriber that never reads.
		// Ingest calls Notify on its hot path: if this can block, one frozen
		// terminal stalls the whole pipeline.
		for range 100 {
			b.Notify(ctx, model.Vulnerability{CVEID: "CVE-2021-44228"})
		}

		delivered, dropped := b.Stats()
		Expect(delivered).To(Equal(int64(2)), "only the buffer should have been filled")
		Expect(dropped).To(Equal(int64(98)), "the rest should be dropped, not queued")
	})

	It("stops delivering once a subscription ends, and closes its channel", func() {
		b := broadcast.New(4)
		updates, stop := b.Subscribe()

		stop()

		// A closed channel is how the reader learns the feed is over.
		Eventually(updates).Should(BeClosed())
		Expect(b.Subscribers()).To(BeZero())

		// And Notify must not panic by writing to it.
		Expect(func() { b.Notify(ctx, model.Vulnerability{CVEID: "CVE-2024-1"}) }).NotTo(Panic())
	})

	It("tolerates a subscription being stopped twice", func() {
		b := broadcast.New(4)
		_, stop := b.Subscribe()

		stop()
		// A deferred stop after an explicit one is ordinary in a server
		// handler, and closing a closed channel would panic.
		Expect(stop).NotTo(Panic())
	})

	It("delivers nothing when nobody is watching, which is the normal case", func() {
		b := broadcast.New(4)

		b.Notify(ctx, model.Vulnerability{CVEID: "CVE-2021-44228"})

		delivered, dropped := b.Stats()
		Expect(delivered).To(BeZero())
		Expect(dropped).To(BeZero())
	})
})
