package tui

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestTUI(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Deck TUI Suite")
}

var _ = Describe("tui entrypoint", func() {
	It("loads the test harness", func() {
		Expect(true).To(BeTrue())
	})
})
