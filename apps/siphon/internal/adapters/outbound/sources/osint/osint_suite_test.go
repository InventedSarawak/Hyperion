package osint_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestOSINT(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Siphon osint Adapter Suite")
}
