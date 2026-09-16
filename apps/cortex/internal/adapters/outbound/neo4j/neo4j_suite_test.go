package neo4j_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestNeo4j(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Cortex Neo4j Adapter Suite")
}
