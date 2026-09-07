package osv_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestOSV(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Siphon OSV Mapping Suite")
}
