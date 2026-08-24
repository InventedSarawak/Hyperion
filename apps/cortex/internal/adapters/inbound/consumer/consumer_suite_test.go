package consumer_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestConsumer(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Cortex Consumer Adapter Suite")
}
