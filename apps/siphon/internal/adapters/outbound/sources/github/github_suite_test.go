package github_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestGITHUB(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Siphon github Adapter Suite")
}
