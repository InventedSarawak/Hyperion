package osvbulk_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestOSVBulk(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Siphon OSV Bulk Export Suite")
}
