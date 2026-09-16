// Package publisher holds OUTBOUND adapters implementing ports.SignalPublisher.
// This is the boundary where siphon's domain event is mapped onto the wire
// contract (hyperion.events.v1.SignalDiscovered). The rest of siphon never
// touches the generated protobuf types — only this package does.
package publisher

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/common/v1"
	eventsv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/events/v1"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/events"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// Stdout publishes each event as a line of protojson to an io.Writer. It is a
// stand-in for the eventual Kafka publisher; both implement ports.SignalPublisher.
type Stdout struct {
	w         io.Writer
	marshaler protojson.MarshalOptions
}

// NewStdout builds a publisher writing to w (defaults to os.Stdout when nil).
func NewStdout(w io.Writer) *Stdout {
	if w == nil {
		w = os.Stdout
	}
	return &Stdout{w: w, marshaler: protojson.MarshalOptions{}}
}

// Publish maps the domain event to its protobuf form and writes it out.
func (p *Stdout) Publish(_ context.Context, evt events.SignalDiscovered) error {
	b, err := p.marshaler.Marshal(toProto(evt))
	if err != nil {
		return fmt.Errorf("publisher: marshal signal %s: %w", evt.SignalID, err)
	}
	if _, err := fmt.Fprintln(p.w, string(b)); err != nil {
		return fmt.Errorf("publisher: write signal %s: %w", evt.SignalID, err)
	}
	return nil
}

// --- mapping: domain -> wire contract ---

func toProto(evt events.SignalDiscovered) *eventsv1.SignalDiscovered {
	return &eventsv1.SignalDiscovered{
		SignalId:      evt.SignalID,
		Source:        toProtoSourceKind(evt.Source),
		Vulnerability: toProtoVulnerability(evt.Signal),
		DiscoveredAt:  toTimestamp(evt.DiscoveredAt),
		RawRef:        evt.RawRef,
	}
}

func toProtoVulnerability(s model.SourceSignal) *commonv1.Vulnerability {
	return &commonv1.Vulnerability{
		CveId:            s.CVEID,
		Aliases:          s.Aliases,
		Kind:             toProtoKind(s.Kind),
		Title:            s.Title,
		Description:      s.Description,
		Scores:           toProtoScores(s.Scores),
		References:       s.References,
		PublishedAt:      toTimestamp(s.PublishedAt),
		ModifiedAt:       toTimestamp(s.ModifiedAt),
		AffectedPackages: toProtoPackageRefs(s.AffectedPackages),
	}
}

// toProtoKind maps the finding kind. An unset kind goes out unspecified,
// which cortex reads as an ordinary vulnerability.
func toProtoKind(k model.FindingKind) commonv1.FindingKind {
	switch k {
	case model.KindMalware:
		return commonv1.FindingKind_FINDING_KIND_MALWARE
	case model.KindVulnerability:
		return commonv1.FindingKind_FINDING_KIND_VULNERABILITY
	default:
		return commonv1.FindingKind_FINDING_KIND_UNSPECIFIED
	}
}

func toProtoPackageRefs(refs []valueobject.PackageRef) []*commonv1.PackageRef {
	if len(refs) == 0 {
		return nil
	}
	out := make([]*commonv1.PackageRef, 0, len(refs))
	for _, r := range refs {
		if r.Validate() != nil {
			continue
		}
		out = append(out, &commonv1.PackageRef{
			Ecosystem: toProtoEcosystem(r.Ecosystem),
			Name:      r.Name,
			Version:   r.Version,
		})
	}
	return out
}

func toProtoEcosystem(e valueobject.Ecosystem) commonv1.Ecosystem {
	switch e {
	case valueobject.EcosystemGo:
		return commonv1.Ecosystem_ECOSYSTEM_GO
	case valueobject.EcosystemNPM:
		return commonv1.Ecosystem_ECOSYSTEM_NPM
	case valueobject.EcosystemPyPI:
		return commonv1.Ecosystem_ECOSYSTEM_PYPI
	case valueobject.EcosystemMaven:
		return commonv1.Ecosystem_ECOSYSTEM_MAVEN
	case valueobject.EcosystemCargo:
		return commonv1.Ecosystem_ECOSYSTEM_CARGO
	case valueobject.EcosystemRubyGems:
		return commonv1.Ecosystem_ECOSYSTEM_RUBYGEMS
	case valueobject.EcosystemNuGet:
		return commonv1.Ecosystem_ECOSYSTEM_NUGET
	case valueobject.EcosystemPackagist:
		return commonv1.Ecosystem_ECOSYSTEM_PACKAGIST
	default:
		return commonv1.Ecosystem_ECOSYSTEM_UNSPECIFIED
	}
}

func toProtoScores(scores []model.CVSS) []*commonv1.Cvss {
	out := make([]*commonv1.Cvss, 0, len(scores))
	for _, s := range scores {
		out = append(out, &commonv1.Cvss{
			Version:   s.Version,
			BaseScore: s.BaseScore,
			Vector:    s.Vector,
			Severity:  toProtoSeverity(s.Severity),
		})
	}
	return out
}

func toProtoSourceKind(k valueobject.SourceKind) eventsv1.SourceKind {
	switch k {
	case valueobject.SourceKindNVD:
		return eventsv1.SourceKind_SOURCE_KIND_NVD
	case valueobject.SourceKindGitHubAdvisory:
		return eventsv1.SourceKind_SOURCE_KIND_GITHUB_ADVISORY
	case valueobject.SourceKindCISAKEV:
		return eventsv1.SourceKind_SOURCE_KIND_CISA_KEV
	case valueobject.SourceKindExploitDB:
		return eventsv1.SourceKind_SOURCE_KIND_EXPLOIT_DB
	case valueobject.SourceKindMITRE:
		return eventsv1.SourceKind_SOURCE_KIND_MITRE
	case valueobject.SourceKindVendorAdvisory:
		return eventsv1.SourceKind_SOURCE_KIND_VENDOR_ADVISORY
	case valueobject.SourceKindOSINT:
		return eventsv1.SourceKind_SOURCE_KIND_OSINT
	case valueobject.SourceKindPackageFeed:
		return eventsv1.SourceKind_SOURCE_KIND_PACKAGE_FEED
	case valueobject.SourceKindShodan:
		return eventsv1.SourceKind_SOURCE_KIND_SHODAN
	case valueobject.SourceKindGSD:
		return eventsv1.SourceKind_SOURCE_KIND_GSD
	default:
		return eventsv1.SourceKind_SOURCE_KIND_UNSPECIFIED
	}
}

func toProtoSeverity(s model.Severity) commonv1.Severity {
	switch s {
	case model.SeverityNone:
		return commonv1.Severity_SEVERITY_NONE
	case model.SeverityLow:
		return commonv1.Severity_SEVERITY_LOW
	case model.SeverityMedium:
		return commonv1.Severity_SEVERITY_MEDIUM
	case model.SeverityHigh:
		return commonv1.Severity_SEVERITY_HIGH
	case model.SeverityCritical:
		return commonv1.Severity_SEVERITY_CRITICAL
	default:
		return commonv1.Severity_SEVERITY_UNSPECIFIED
	}
}

func toTimestamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}
