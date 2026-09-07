package vendor_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestVENDOR(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Siphon vendor Adapter Suite")
}
