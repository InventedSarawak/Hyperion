package main

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestTUICommand(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Deck Command Suite")
}
