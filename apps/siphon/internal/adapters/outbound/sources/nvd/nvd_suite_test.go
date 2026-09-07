package nvd_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestNVD(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Siphon NVD Adapter Suite")
}
