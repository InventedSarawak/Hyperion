package e2e_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestBlackBox(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Hyperion Black-Box Suite")
}
