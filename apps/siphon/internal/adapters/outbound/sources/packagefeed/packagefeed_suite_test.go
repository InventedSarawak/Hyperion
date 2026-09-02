package packagefeed_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestPACKAGEFEED(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Siphon packagefeed Adapter Suite")
}
