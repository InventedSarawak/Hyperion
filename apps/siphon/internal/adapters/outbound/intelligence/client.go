// Package intelligence is an OUTBOUND adapter implementing
// ports.DependencyPublisher by calling cortex's IntelligenceService over gRPC.
// It is the only place in siphon that touches the generated contract types for
// dependency reporting.
//
// siphon does not own the graph: it observes manifests and reports them.
// Where the source-signal path publishes an event, this path makes a call —
// v2 has no message bus yet, so this coupling is deliberate and temporary
// (docs/TODO.md v3 moves it onto Kafka; only this adapter changes).
package intelligence

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/common/v1"
	intelv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/intelligence/v1"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// Client wraps the generated gRPC stub.
type Client struct {
	conn    *grpc.ClientConn
	stub    intelv1.IntelligenceServiceClient
	timeout time.Duration
}

// Dial opens a connection to cortex. Local development uses plaintext; TLS
// credentials belong here once the services are deployed apart (v4).
func Dial(addr string) (*Client, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("intelligence: dial %s: %w", addr, err)
	}
	return &Client{
		conn:    conn,
		stub:    intelv1.NewIntelligenceServiceClient(conn),
		timeout: 30 * time.Second,
	}, nil
}

// Close releases the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Publish sends one manifest read and reports how many edges cortex wrote.
func (c *Client) Publish(ctx context.Context, snapshot model.RepositorySnapshot) (int, error) {
	if err := snapshot.Validate(); err != nil {
		return 0, err
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.stub.IngestDependencies(ctx, toProtoRequest(snapshot))
	if err != nil {
		return 0, fmt.Errorf("intelligence: ingest dependencies for %s: %w",
			snapshot.Repository.FullName(), err)
	}
	return int(resp.GetDependenciesWritten()), nil
}

// --- mapping: domain -> wire contract ---

func toProtoRequest(s model.RepositorySnapshot) *intelv1.IngestDependenciesRequest {
	deps := make([]*commonv1.Dependency, 0, len(s.Dependencies))
	for _, d := range s.Dependencies {
		if d.Validate() != nil {
			continue
		}
		deps = append(deps, &commonv1.Dependency{
			Package:      toProtoPackageRef(d.Package),
			Direct:       d.Direct,
			ManifestPath: d.ManifestPath,
		})
	}

	req := &intelv1.IngestDependenciesRequest{
		Repository: &commonv1.Repository{
			Owner:         s.Repository.Owner,
			Name:          s.Repository.Name,
			Url:           s.Repository.URL,
			DefaultBranch: s.Repository.DefaultBranch,
		},
		Dependencies: deps,
		Publishes:    toProtoPackageRef(s.Publishes),
	}
	if !s.Author.IsZero() {
		req.Author = &commonv1.Author{Login: s.Author.Login, Name: s.Author.Name, Url: s.Author.URL}
	}
	if !s.ObservedAt.IsZero() {
		req.ObservedAt = timestamppb.New(s.ObservedAt)
	}
	return req
}

func toProtoPackageRef(r valueobject.PackageRef) *commonv1.PackageRef {
	if r.Validate() != nil {
		return nil
	}
	return &commonv1.PackageRef{
		Ecosystem: toProtoEcosystem(r.Ecosystem),
		Name:      r.Name,
		Version:   r.Version,
	}
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
