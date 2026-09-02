package sourcehttp_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSourceHTTP(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Siphon Source HTTP Suite")
}
