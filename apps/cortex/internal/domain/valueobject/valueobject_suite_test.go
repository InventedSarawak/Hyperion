package valueobject_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestValueObject(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Cortex Domain ValueObject Suite")
}
