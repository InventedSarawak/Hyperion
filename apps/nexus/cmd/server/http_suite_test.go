package server

import (
	"net/http"

	"github.com/gavv/httpexpect/v2"
	. "github.com/onsi/ginkgo/v2"
)

var _ = Describe("http api harness", func() {
	It("supports httpexpect against an in-memory handler", func() {
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		httpexpect.WithConfig(httpexpect.Config{
			BaseURL:  "http://nexus.local",
			Client:   &http.Client{Transport: httpexpect.NewBinder(handler)},
			Reporter: httpexpect.NewAssertReporter(GinkgoT()),
		}).GET("/").Expect().Status(http.StatusOK)
	})
})
