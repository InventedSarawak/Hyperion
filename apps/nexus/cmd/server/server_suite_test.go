package server

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestServer(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Nexus Server Suite")
}

var _ = Describe("server entrypoint", func() {
	It("loads the test harness", func() {
		Expect(true).To(BeTrue())
	})
})
