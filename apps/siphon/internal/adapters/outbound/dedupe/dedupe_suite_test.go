package dedupe_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestDedupe(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Siphon Dedupe Suite")
}
