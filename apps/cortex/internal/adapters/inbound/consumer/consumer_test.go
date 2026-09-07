package consumer_test

import (
	"context"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/protobuf/encoding/protojson"

	commonv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/common/v1"
	eventsv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/events/v1"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/inbound/consumer"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
)

// captureIngester records what the consumer would ingest.
type captureIngester struct {
	got []model.Vulnerability
}

func (c *captureIngester) Handle(_ context.Context, v model.Vulnerability) error {
	c.got = append(c.got, v)
	return nil
}

// eventLine renders a SignalDiscovered as a single protojson line.
func eventLine(cve string, sev commonv1.Severity) string {
	msg := &eventsv1.SignalDiscovered{
		SignalId: "nvd:" + cve,
		Source:   eventsv1.SourceKind_SOURCE_KIND_NVD,
		Vulnerability: &commonv1.Vulnerability{
			CveId:  cve,
			Scores: []*commonv1.Cvss{{Version: "3.1", BaseScore: 9.8, Severity: sev}},
		},
	}
	b, err := protojson.Marshal(msg)
	Expect(err).ToNot(HaveOccurred())
	return string(b)
}

var _ = Describe("Consumer", func() {
	ctx := context.Background()

	It("maps protojson events into domain vulnerabilities and ingests them", func() {
		input := strings.Join([]string{
			eventLine("CVE-2021-44228", commonv1.Severity_SEVERITY_CRITICAL),
			eventLine("CVE-2021-45046", commonv1.Severity_SEVERITY_HIGH),
		}, "\n")

		ing := &captureIngester{}
		n, err := consumer.NewConsumer(ing).Run(ctx, strings.NewReader(input))

		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(2))
		Expect(ing.got).To(HaveLen(2))
		Expect(ing.got[0].CVEID).To(Equal("CVE-2021-44228"))
		Expect(ing.got[0].Sources).To(Equal([]string{"nvd"}))
		Expect(ing.got[0].Scores[0].Severity).To(Equal(model.SeverityCritical))
	})

	It("skips malformed and blank lines but keeps going", func() {
		input := strings.Join([]string{
			eventLine("CVE-1", commonv1.Severity_SEVERITY_LOW),
			"",
			"{ not valid protojson",
			eventLine("CVE-2", commonv1.Severity_SEVERITY_MEDIUM),
		}, "\n")

		ing := &captureIngester{}
		n, err := consumer.NewConsumer(ing).Run(ctx, strings.NewReader(input))

		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(2))
	})
})
