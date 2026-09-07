package cisakev_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCISAKEV(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Siphon cisakev Adapter Suite")
}
