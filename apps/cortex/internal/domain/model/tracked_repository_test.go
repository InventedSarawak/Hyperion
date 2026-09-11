package model_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
)

var _ = Describe("TrackedRepository", func() {
	DescribeTable("parses what people actually type or paste",
		func(raw, owner, name string) {
			repo, err := model.ParseTrackedRepository(raw)
			Expect(err).ToNot(HaveOccurred())
			Expect(repo.Owner).To(Equal(owner))
			Expect(repo.Name).To(Equal(name))
			Expect(repo.Status).To(Equal(model.ScanPending))
		},
		Entry("owner/name", "vercel/next.js", "vercel", "next.js"),
		Entry("padded", "  gin-gonic/gin ", "gin-gonic", "gin"),
		Entry("a pasted URL", "https://github.com/eslint/eslint", "eslint", "eslint"),
		Entry("a clone URL", "https://github.com/ajv-validator/ajv.git", "ajv-validator", "ajv"),
		Entry("a trailing slash", "github.com/facebook/react/", "facebook", "react"),
	)

	DescribeTable("rejects anything that is not one repository",
		func(raw string) {
			_, err := model.ParseTrackedRepository(raw)
			Expect(err).To(MatchError(model.ErrInvalidRepositoryName))
		},
		Entry("an owner alone", "vercel"),
		Entry("empty", ""),
		Entry("a path", "vercel/next.js/tree/canary"),
		Entry("spaces", "vercel/next js"),
		Entry("injection", "vercel/../../etc"),
	)

	It("builds its URL and full name", func() {
		repo := model.TrackedRepository{Owner: "vercel", Name: "next.js"}
		Expect(repo.FullName()).To(Equal("vercel/next.js"))
		Expect(repo.URL()).To(Equal("https://github.com/vercel/next.js"))
	})
})
