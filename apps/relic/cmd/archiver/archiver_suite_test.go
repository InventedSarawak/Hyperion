package archiver

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestArchiver(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Relic Archiver Suite")
}

var _ = Describe("archiver entrypoint", func() {
	It("loads the test harness", func() {
		Expect(true).To(BeTrue())
	})
})
