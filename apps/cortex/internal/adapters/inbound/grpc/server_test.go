package grpc_test

import (
	"context"
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	commonv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/common/v1"
	intelv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/intelligence/v1"

	grpcadapter "github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/inbound/grpc"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/queries"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
)

// stubSearcher stands in for the search use case.
type stubSearcher struct {
	gotQuery string
	gotSize  int
	gotToken string
	result   queries.Result
	err      error
}

func (s *stubSearcher) Handle(_ context.Context, q string, size int, token string) (queries.Result, error) {
	s.gotQuery, s.gotSize, s.gotToken = q, size, token
	return s.result, s.err
}

var _ = Describe("gRPC Server", func() {
	ctx := context.Background()

	It("maps a domain result onto the wire contract", func() {
		stub := &stubSearcher{result: queries.Result{
			Hits: []model.SearchHit{{
				Vulnerability: model.Vulnerability{
					CVEID:       "CVE-2021-44228",
					Title:       "log4shell",
					Description: "JNDI lookup",
					Scores:      []model.CVSS{{Version: "3.1", BaseScore: 10, Severity: model.SeverityCritical}},
					References:  []string{"https://example.test/a"},
					PublishedAt: time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC),
				},
				Score: 8.5,
			}},
			NextPageToken: "25",
		}}

		resp, err := grpcadapter.NewServer(stub).Search(ctx, &intelv1.SearchRequest{
			Query:    "log4j",
			PageSize: 25,
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(stub.gotQuery).To(Equal("log4j"))
		Expect(stub.gotSize).To(Equal(25))
		Expect(resp.GetNextPageToken()).To(Equal("25"))
		Expect(resp.GetResults()).To(HaveLen(1))

		got := resp.GetResults()[0]
		Expect(got.GetScore()).To(Equal(8.5))
		Expect(got.GetVulnerability().GetCveId()).To(Equal("CVE-2021-44228"))
		Expect(got.GetVulnerability().GetScores()[0].GetSeverity()).To(Equal(commonv1.Severity_SEVERITY_CRITICAL))
		Expect(got.GetVulnerability().GetPublishedAt().AsTime().Year()).To(Equal(2021))
	})

	It("forwards the page token", func() {
		stub := &stubSearcher{}
		_, err := grpcadapter.NewServer(stub).Search(ctx, &intelv1.SearchRequest{Query: "log4j", PageToken: "50"})

		Expect(err).ToNot(HaveOccurred())
		Expect(stub.gotToken).To(Equal("50"))
	})

	It("returns InvalidArgument when the use case rejects the request", func() {
		stub := &stubSearcher{err: errors.New("query must not be empty")}

		_, err := grpcadapter.NewServer(stub).Search(ctx, &intelv1.SearchRequest{})

		Expect(err).To(HaveOccurred())
		Expect(status.Code(err)).To(Equal(codes.InvalidArgument))
	})
})
