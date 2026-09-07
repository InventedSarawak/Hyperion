package gsd_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestGSD(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Siphon gsd Adapter Suite")
}
