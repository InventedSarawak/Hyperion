package consumer_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/protobuf/encoding/protojson"

	commonv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/common/v1"
	eventsv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/events/v1"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/adapters/inbound/consumer"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
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

var _ = Describe("Consumer affected packages", func() {
	It("maps affected packages off the wire into the domain", func() {
		msg := &eventsv1.SignalDiscovered{
			SignalId: "github_advisory:CVE-2021-44228",
			Source:   eventsv1.SourceKind_SOURCE_KIND_GITHUB_ADVISORY,
			Vulnerability: &commonv1.Vulnerability{
				CveId: "CVE-2021-44228",
				AffectedPackages: []*commonv1.PackageRef{
					{
						Ecosystem: commonv1.Ecosystem_ECOSYSTEM_MAVEN,
						Name:      "org.apache.logging.log4j:log4j-core",
						Version:   ">= 2.0.1, < 2.15.0",
					},
					{Ecosystem: commonv1.Ecosystem_ECOSYSTEM_UNSPECIFIED, Name: "unmodelled"},
				},
			},
		}
		line, err := protojson.Marshal(msg)
		Expect(err).ToNot(HaveOccurred())

		ingester := &captureIngester{}
		n, err := consumer.NewConsumer(ingester).Run(context.Background(), strings.NewReader(string(line)))

		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(1))
		Expect(ingester.got[0].AffectedPackages).To(HaveLen(2))
		Expect(ingester.got[0].AffectedPackages[0].Key()).To(Equal("maven:org.apache.logging.log4j:log4j-core"))
		Expect(ingester.got[0].AffectedPackages[0].Version).To(Equal(">= 2.0.1, < 2.15.0"))
		Expect(ingester.got[0].AffectedPackages[1].Ecosystem).To(Equal(valueobject.EcosystemUnknown))
	})

	It("maps every id and the kind off the wire, filing the finding under its canonical id", func() {
		msg := &eventsv1.SignalDiscovered{
			SignalId: "package_feed:GHSA-fw8c-xr5c-95f9",
			Source:   eventsv1.SourceKind_SOURCE_KIND_PACKAGE_FEED,
			Vulnerability: &commonv1.Vulnerability{
				CveId:   "MAL-2026-2307",
				Aliases: []string{"GHSA-fw8c-xr5c-95f9"},
				Kind:    commonv1.FindingKind_FINDING_KIND_MALWARE,
			},
		}
		line, err := protojson.Marshal(msg)
		Expect(err).ToNot(HaveOccurred())

		ingester := &captureIngester{}
		_, err = consumer.NewConsumer(ingester).Run(context.Background(), strings.NewReader(string(line)))

		Expect(err).ToNot(HaveOccurred())
		Expect(ingester.got[0].CVEID).To(Equal("GHSA-fw8c-xr5c-95f9"))
		Expect(ingester.got[0].Aliases).To(Equal([]string{"MAL-2026-2307"}))
		Expect(ingester.got[0].Kind).To(Equal(model.KindMalware))
	})

	It("reads an event with no kind as an ordinary vulnerability", func() {
		ingester := &captureIngester{}
		_, err := consumer.NewConsumer(ingester).Run(context.Background(),
			strings.NewReader(eventLine("CVE-2021-44228", commonv1.Severity_SEVERITY_CRITICAL)))

		Expect(err).ToNot(HaveOccurred())
		Expect(ingester.got[0].Kind).To(Equal(model.KindVulnerability))
	})

	It("leaves affected packages nil when the event carries none", func() {
		ingester := &captureIngester{}
		_, err := consumer.NewConsumer(ingester).Run(context.Background(),
			strings.NewReader(eventLine("CVE-2021-44228", commonv1.Severity_SEVERITY_CRITICAL)))

		Expect(err).ToNot(HaveOccurred())
		Expect(ingester.got[0].AffectedPackages).To(BeNil())
	})
})

// orderIngester records, per CVE, the order its events were ingested in.
type orderIngester struct {
	mu    sync.Mutex
	order map[string][]string
}

func (o *orderIngester) Handle(_ context.Context, v model.Vulnerability) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.order[v.CVEID] = append(o.order[v.CVEID], v.Title)
	return nil
}

var _ = Describe("Consumer with several workers", func() {
	It("ingests everything and keeps each CVE's events in input order", func() {
		// Ingest is read-merge-write, so two observations of one CVE must
		// never be merged concurrently or out of order.
		var lines []string
		for seq := 0; seq < 20; seq++ {
			for _, cve := range []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "GHSA-aaaa-bbbb-cccc"} {
				msg := &eventsv1.SignalDiscovered{
					Source:        eventsv1.SourceKind_SOURCE_KIND_NVD,
					Vulnerability: &commonv1.Vulnerability{CveId: cve, Title: fmt.Sprintf("%02d", seq)},
				}
				b, err := protojson.Marshal(msg)
				Expect(err).ToNot(HaveOccurred())
				lines = append(lines, string(b))
			}
		}

		ing := &orderIngester{order: map[string][]string{}}
		n, err := consumer.NewConsumer(ing, consumer.WithWorkers(4)).
			Run(context.Background(), strings.NewReader(strings.Join(lines, "\n")))

		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(80))
		for cve, seen := range ing.order {
			Expect(seen).To(HaveLen(20), cve)
			Expect(sort.StringsAreSorted(seen)).To(BeTrue(), "events for %s arrived out of order: %v", cve, seen)
		}
	})
})

var _ = Describe("Consumer progress", func() {
	ctx := context.Background()

	// captured collects what the consumer logged, at any level.
	captured := func(buf *bytes.Buffer) []map[string]any {
		var out []map[string]any
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if line == "" {
				continue
			}
			var entry map[string]any
			Expect(json.Unmarshal([]byte(line), &entry)).To(Succeed())
			out = append(out, entry)
		}
		return out
	}

	events := func(ids ...string) string {
		var b strings.Builder
		for _, id := range ids {
			b.WriteString(eventLine(id, commonv1.Severity_SEVERITY_HIGH) + "\n")
		}
		return b.String()
	}

	It("reports progress as it goes, so a long run is not silence", func() {
		var buf bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

		n, err := consumer.NewConsumer(&captureIngester{},
			consumer.WithProgressEvery(2), consumer.WithLogger(logger)).
			Run(ctx, strings.NewReader(events("CVE-2021-0001", "CVE-2021-0002", "CVE-2021-0003", "CVE-2021-0004")))

		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(4))

		var progress []map[string]any
		for _, entry := range captured(&buf) {
			if entry["msg"] == "ingest progress" {
				progress = append(progress, entry)
			}
		}
		Expect(progress).To(HaveLen(2), "one line every two findings")
		Expect(progress[1]["ingested"]).To(BeNumerically("==", 4))
		Expect(progress[1]).To(HaveKey("per_second"))
		Expect(progress[1]).To(HaveKey("latest"))
	})

	It("says nothing per finding at info, and names each one at debug", func() {
		var quiet, verbose bytes.Buffer
		lines := events("CVE-2021-0001", "CVE-2021-0002")

		_, err := consumer.NewConsumer(&captureIngester{}, consumer.WithProgressEvery(0),
			consumer.WithLogger(slog.New(slog.NewJSONHandler(&quiet, &slog.HandlerOptions{Level: slog.LevelInfo})))).
			Run(ctx, strings.NewReader(lines))
		Expect(err).ToNot(HaveOccurred())
		Expect(strings.TrimSpace(quiet.String())).To(BeEmpty(), "nothing to say when all is well")

		_, err = consumer.NewConsumer(&captureIngester{}, consumer.WithProgressEvery(0),
			consumer.WithLogger(slog.New(slog.NewJSONHandler(&verbose, &slog.HandlerOptions{Level: slog.LevelDebug})))).
			Run(ctx, strings.NewReader(lines))
		Expect(err).ToNot(HaveOccurred())

		var ingested []string
		for _, entry := range captured(&verbose) {
			if entry["msg"] == "ingested" {
				ingested = append(ingested, entry["id"].(string))
			}
		}
		Expect(ingested).To(ConsistOf("CVE-2021-0001", "CVE-2021-0002"))
	})
})
