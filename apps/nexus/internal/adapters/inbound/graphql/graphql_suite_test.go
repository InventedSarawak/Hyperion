package graphql_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestGraphQL(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Nexus GraphQL Adapter Suite")
}
