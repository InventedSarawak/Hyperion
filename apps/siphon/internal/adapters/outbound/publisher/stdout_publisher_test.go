package publisher_test

import (
	"bytes"
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/protobuf/encoding/protojson"

	eventsv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/events/v1"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/publisher"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/events"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

var _ = Describe("Stdout Publisher", func() {
	It("marshals a domain event onto the wire contract faithfully", func() {
		var buf bytes.Buffer
		evt := events.NewSignalDiscovered(
			valueobject.SourceKindNVD,
			model.SourceSignal{
				CVEID:       "CVE-2021-44228",
				Description: "log4shell",
				Scores:      []model.CVSS{{Version: "3.1", BaseScore: 10.0, Severity: model.SeverityCritical}},
				References:  []string{"https://example.test/a"},
				PublishedAt: time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC),
			},
			time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			"",
		)

		err := publisher.NewStdout(&buf).Publish(context.Background(), evt)
		Expect(err).ToNot(HaveOccurred())

		// Round-trip: parse the emitted protojson back into the proto message.
		var got eventsv1.SignalDiscovered
		Expect(protojson.Unmarshal(buf.Bytes(), &got)).To(Succeed())

		Expect(got.GetSignalId()).To(Equal("nvd:CVE-2021-44228"))
		Expect(got.GetSource()).To(Equal(eventsv1.SourceKind_SOURCE_KIND_NVD))
		Expect(got.GetVulnerability().GetCveId()).To(Equal("CVE-2021-44228"))
		Expect(got.GetVulnerability().GetScores()).To(HaveLen(1))
		Expect(got.GetVulnerability().GetScores()[0].GetBaseScore()).To(Equal(10.0))
		Expect(got.GetVulnerability().GetPublishedAt().AsTime().Year()).To(Equal(2021))
	})
})

var _ = Describe("source kind coverage", func() {
	It("maps every domain source kind onto a distinct wire enum value", func() {
		// Regression: six sources were added to the domain without proto enum
		// values, so their provenance silently decoded as UNSPECIFIED.
		seen := map[eventsv1.SourceKind]valueobject.SourceKind{}

		for _, kind := range valueobject.AllSourceKinds() {
			var buf bytes.Buffer
			evt := events.NewSignalDiscovered(kind, model.SourceSignal{CVEID: "CVE-1"}, time.Now(), "")
			Expect(publisher.NewStdout(&buf).Publish(context.Background(), evt)).To(Succeed())

			var got eventsv1.SignalDiscovered
			Expect(protojson.Unmarshal(buf.Bytes(), &got)).To(Succeed())

			Expect(got.GetSource()).ToNot(Equal(eventsv1.SourceKind_SOURCE_KIND_UNSPECIFIED),
				"domain kind %q has no proto enum value", kind)
			Expect(seen).ToNot(HaveKey(got.GetSource()),
				"domain kinds %q and %q collide on the same enum value", kind, seen[got.GetSource()])
			seen[got.GetSource()] = kind
		}
		Expect(seen).To(HaveLen(len(valueobject.AllSourceKinds())))
	})
})
