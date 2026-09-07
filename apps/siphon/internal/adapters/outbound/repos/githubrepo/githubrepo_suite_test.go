package githubrepo_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestGithubRepo(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Siphon GitHub Repository Adapter Suite")
}
