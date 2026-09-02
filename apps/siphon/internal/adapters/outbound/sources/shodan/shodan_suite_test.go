package shodan_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSHODAN(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Siphon shodan Adapter Suite")
}
