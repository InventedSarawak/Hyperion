package worker

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestWorker(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Siphon Worker Suite")
}

var _ = Describe("worker entrypoint", func() {
	It("loads the test harness", func() {
		Expect(true).To(BeTrue())
	})
})
