// Package events holds siphon's domain events: facts about something that
// happened, which the service publishes for other services to react to.
package events

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// SignalDiscovered is emitted when siphon observes a vulnerability signal from
// an upstream source. It is the domain event; an outbound adapter maps it onto
// the wire contract (hyperion.events.v1.SignalDiscovered) at the boundary.
type SignalDiscovered struct {
	SignalID     string // stable dedupe / idempotency key
	Source       valueobject.SourceKind
	Signal       model.SourceSignal
	DiscoveredAt time.Time
	RawRef       string // pointer to the archived raw payload, if any
}

// NewSignalDiscovered builds the event and derives its identity. The SignalID
// is deterministic (source + CVE id) so re-observing the same signal yields the
// same key — that dedupe rule is domain logic, not adapter concern.
func NewSignalDiscovered(source valueobject.SourceKind, sig model.SourceSignal, discoveredAt time.Time, rawRef string) SignalDiscovered {
	return SignalDiscovered{
		SignalID:     fmt.Sprintf("%s:%s", source, sig.CVEID),
		Source:       source,
		Signal:       sig,
		DiscoveredAt: discoveredAt,
		RawRef:       rawRef,
	}
}

// Fingerprint identifies this exact observation of a signal: its identity plus
// a digest of everything downstream would act on.
//
// The SignalID alone is not enough to deduplicate against. It is source + id,
// so it is the same every time a feed reports the same advisory — including
// when the feed reports it *differently*, with a score it did not have
// yesterday or a newly named affected package. Suppressing on identity would
// mean the correction is never published, which is worse than the duplicate it
// avoids.
//
// Slice fields are sorted into a copy before hashing: feeds do not promise a
// stable order, and an unchanged advisory whose references came back shuffled
// must not look like new information.
func (e SignalDiscovered) Fingerprint() string {
	h := sha256.New()

	write := func(parts ...string) {
		for _, p := range parts {
			_, _ = io.WriteString(h, p)
			_, _ = h.Write([]byte{0}) // separator: "ab"+"c" must not equal "a"+"bc"
		}
	}

	sorted := func(in []string) []string {
		out := slices.Clone(in)
		sort.Strings(out)
		return out
	}

	s := e.Signal
	write(e.SignalID, e.Source.String(), s.CVEID, string(s.Kind), s.Title, s.Description)
	write(sorted(s.Aliases)...)
	write(sorted(s.References)...)
	write(s.PublishedAt.UTC().Format(time.RFC3339Nano), s.ModifiedAt.UTC().Format(time.RFC3339Nano))

	scores := make([]string, 0, len(s.Scores))
	for _, c := range s.Scores {
		scores = append(scores, fmt.Sprintf("%s|%s|%s|%s",
			c.Version, strconv.FormatFloat(c.BaseScore, 'f', -1, 64), c.Vector, string(c.Severity)))
	}
	write(sorted(scores)...)

	packages := make([]string, 0, len(s.AffectedPackages))
	for _, pkg := range s.AffectedPackages {
		packages = append(packages, fmt.Sprintf("%s|%s|%s", pkg.Ecosystem, pkg.Name, pkg.Version))
	}
	write(sorted(packages)...)

	return hex.EncodeToString(h.Sum(nil))
}
