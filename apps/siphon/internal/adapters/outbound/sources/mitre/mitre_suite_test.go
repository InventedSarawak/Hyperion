package mitre_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestMITRE(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Siphon mitre Adapter Suite")
}
