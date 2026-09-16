package events_test

import (
	"slices"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/events"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

var _ = Describe("SignalDiscovered fingerprint", func() {
	var (
		at     = time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC)
		signal = model.SourceSignal{
			CVEID:       "CVE-2021-44228",
			Aliases:     []string{"GHSA-jfh8-c2jp-5v3q"},
			Kind:        model.KindVulnerability,
			Title:       "Log4Shell",
			Description: "JNDI lookup in log4j2",
			Scores:      []model.CVSS{{Version: "3.1", BaseScore: 10, Vector: "AV:N", Severity: model.SeverityCritical}},
			References:  []string{"https://a.example", "https://b.example"},
			PublishedAt: at,
			ModifiedAt:  at,
			AffectedPackages: []valueobject.PackageRef{
				{Ecosystem: valueobject.EcosystemMaven, Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1"},
			},
		}
	)

	fingerprint := func(s model.SourceSignal) string {
		return events.NewSignalDiscovered(valueobject.SourceKindNVD, s, at, "").Fingerprint()
	}

	// copyOf deep-copies the slice fields. Assigning the struct alone shares
	// their backing arrays, so mutating the copy would silently mutate the
	// original and both fingerprints would hash the same data.
	copyOf := func(s model.SourceSignal) model.SourceSignal {
		out := s
		out.Aliases = slices.Clone(s.Aliases)
		out.References = slices.Clone(s.References)
		out.Scores = slices.Clone(s.Scores)
		out.AffectedPackages = slices.Clone(s.AffectedPackages)
		return out
	}

	It("is the same for the same observation seen twice", func() {
		// The whole point: a poll re-reads its window, so the same advisory
		// arrives again and again and must be recognised.
		Expect(fingerprint(signal)).To(Equal(fingerprint(signal)))
	})

	It("does not depend on the order a feed happened to return lists in", func() {
		shuffled := signal
		shuffled.References = []string{"https://b.example", "https://a.example"}

		Expect(fingerprint(shuffled)).To(Equal(fingerprint(signal)))
	})

	It("does not mutate the signal it hashes", func() {
		unsorted := copyOf(signal)
		unsorted.References = []string{"https://b.example", "https://a.example"}
		_ = fingerprint(unsorted)

		Expect(unsorted.References).To(Equal([]string{"https://b.example", "https://a.example"}))
	})

	DescribeTable("changes when the observation changes, so a correction is still published",
		func(mutate func(*model.SourceSignal)) {
			before := fingerprint(signal)

			changed := copyOf(signal)
			mutate(&changed)

			Expect(fingerprint(changed)).NotTo(Equal(before))
		},
		Entry("a title arrives", func(s *model.SourceSignal) { s.Title = "Log4Shell (updated)" }),
		Entry("the description is rewritten", func(s *model.SourceSignal) { s.Description = "different" }),
		Entry("a score is added", func(s *model.SourceSignal) {
			s.Scores = append(s.Scores, model.CVSS{Version: "4.0", BaseScore: 9.8})
		}),
		Entry("a score is corrected", func(s *model.SourceSignal) {
			s.Scores = []model.CVSS{{Version: "3.1", BaseScore: 9.8, Vector: "AV:N", Severity: model.SeverityCritical}}
		}),
		Entry("a reference is added", func(s *model.SourceSignal) {
			s.References = append(s.References, "https://c.example")
		}),
		Entry("an alias is added", func(s *model.SourceSignal) {
			s.Aliases = append(s.Aliases, "CVE-2021-45046")
		}),
		Entry("a newly affected package is named", func(s *model.SourceSignal) {
			s.AffectedPackages = append(s.AffectedPackages,
				valueobject.PackageRef{Ecosystem: valueobject.EcosystemMaven, Name: "org.apache.logging.log4j:log4j-api", Version: "2.14.1"})
		}),
		Entry("the affected version range changes", func(s *model.SourceSignal) {
			s.AffectedPackages[0].Version = "2.15.0"
		}),
		Entry("the feed amends the modified date", func(s *model.SourceSignal) {
			s.ModifiedAt = at.Add(time.Hour)
		}),
		Entry("it is reclassified as malware", func(s *model.SourceSignal) { s.Kind = model.KindMalware }),
	)

	It("differs between two sources reporting the same finding", func() {
		fromNVD := events.NewSignalDiscovered(valueobject.SourceKindNVD, signal, at, "").Fingerprint()
		fromGitHub := events.NewSignalDiscovered(valueobject.SourceKindGitHubAdvisory, signal, at, "").Fingerprint()

		// Each source's view is its own observation: cortex merges them, and
		// suppressing one because another got there first would lose it.
		Expect(fromNVD).NotTo(Equal(fromGitHub))
	})

	It("ignores when it was discovered, which changes on every poll", func() {
		later := events.NewSignalDiscovered(valueobject.SourceKindNVD, signal, at.Add(24*time.Hour), "").Fingerprint()

		Expect(later).To(Equal(fingerprint(signal)))
	})
})
