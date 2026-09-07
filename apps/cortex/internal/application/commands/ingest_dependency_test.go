package commands_test

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/commands"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// memGraph is an in-memory DependencyGraph (outbound port) for tests.
type memGraph struct {
	snapshots []model.RepositorySnapshot
	links     map[string][]valueobject.PackageRef
	writeErr  error
}

func newMemGraph() *memGraph {
	return &memGraph{links: map[string][]valueobject.PackageRef{}}
}

func (m *memGraph) UpsertRepositorySnapshot(_ context.Context, s model.RepositorySnapshot) (int, error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	m.snapshots = append(m.snapshots, s)
	return len(s.ValidDependencies()), nil
}

func (m *memGraph) LinkVulnerability(_ context.Context, cveID string, pkgs []valueobject.PackageRef) error {
	if m.writeErr != nil {
		return m.writeErr
	}
	m.links[cveID] = append(m.links[cveID], pkgs...)
	return nil
}

func (m *memGraph) FindBlastRadius(context.Context, string, int, int) (model.BlastRadius, error) {
	return model.BlastRadius{}, nil
}

func (m *memGraph) Ready(context.Context) error { return nil }

var _ = Describe("IngestDependency use case", func() {
	ctx := context.Background()

	snapshot := func(deps ...model.Dependency) model.RepositorySnapshot {
		return model.RepositorySnapshot{
			Repository:   model.Repository{Owner: "gin-gonic", Name: "gin"},
			Author:       model.Author{Login: "gin-gonic"},
			Dependencies: deps,
		}
	}
	goDep := func(name string, direct bool) model.Dependency {
		return model.Dependency{
			Package:      valueobject.NewPackageRef("go", name, "v1.0.0"),
			Direct:       direct,
			ManifestPath: "go.mod",
		}
	}

	It("writes a manifest to the graph and reports the edges written", func() {
		graph := newMemGraph()

		n, err := commands.NewIngestDependency(graph).Handle(ctx,
			snapshot(goDep("golang.org/x/net", true), goDep("golang.org/x/sys", false)))

		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(2))
		Expect(graph.snapshots).To(HaveLen(1))
		Expect(graph.snapshots[0].Repository.FullName()).To(Equal("gin-gonic/gin"))
	})

	It("rejects a snapshot whose repository does not identify itself", func() {
		_, err := commands.NewIngestDependency(newMemGraph()).Handle(ctx, model.RepositorySnapshot{})
		Expect(err).To(MatchError(model.ErrMissingRepositoryIdentity))
	})

	It("accepts a repository with no dependencies: that is a fact, not a failure", func() {
		graph := newMemGraph()

		n, err := commands.NewIngestDependency(graph).Handle(ctx, snapshot())

		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(0))
		Expect(graph.snapshots).To(HaveLen(1))
	})

	It("reports that the graph is unavailable rather than silently dropping writes", func() {
		_, err := commands.NewIngestDependency(nil).Handle(ctx, snapshot(goDep("golang.org/x/net", true)))
		Expect(err).To(MatchError(ports.ErrGraphUnavailable))
	})

	It("wraps a backend failure with the repository it was writing", func() {
		graph := newMemGraph()
		graph.writeErr = errors.New("bolt: connection refused")

		_, err := commands.NewIngestDependency(graph).Handle(ctx, snapshot(goDep("golang.org/x/net", true)))

		Expect(err).To(MatchError(ContainSubstring("gin-gonic/gin")))
		Expect(err).To(MatchError(ContainSubstring("connection refused")))
	})
})
