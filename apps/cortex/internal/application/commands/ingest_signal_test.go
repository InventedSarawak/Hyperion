package commands_test

import (
	"context"
	"errors"
	"sort"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/commands"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// observed wraps a finding as an ordinary, current observation — what a poll
// produces, as opposed to a backfill replaying history.
func observed(v model.Vulnerability) commands.Observation {
	return commands.Observation{Vulnerability: v}
}

// memRepo is an in-memory VulnerabilityRepo (outbound port) for tests. It
// resolves aliases and retires replaced keys like the real repo.
type memRepo struct {
	store    map[string]model.Vulnerability
	upserts  int
	conflict int // fail this many upserts with ErrConflict first
}

func newMemRepo() *memRepo { return &memRepo{store: map[string]model.Vulnerability{}} }

func (m *memRepo) Upsert(_ context.Context, v model.Vulnerability, replaces ...string) error {
	m.upserts++
	if m.conflict > 0 {
		m.conflict--
		return ports.ErrConflict
	}
	for _, id := range replaces {
		delete(m.store, id)
	}
	m.store[v.CVEID] = v
	return nil
}

func (m *memRepo) FindByIDs(_ context.Context, ids []string) ([]model.Vulnerability, error) {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var out []model.Vulnerability
	for _, v := range m.store {
		for _, id := range v.IDs() {
			if want[id] {
				out = append(out, v)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CVEID < out[j].CVEID })
	return out, nil
}

func (m *memRepo) GetByID(ctx context.Context, id string) (model.Vulnerability, error) {
	found, _ := m.FindByIDs(ctx, []string{id})
	if len(found) == 0 {
		return model.Vulnerability{}, ports.ErrNotFound
	}
	return found[0], nil
}

func (m *memRepo) Count(_ context.Context) (int, error) { return len(m.store), nil }

// Delete removes findings by any id they are stored under.
func (m *memRepo) Delete(_ context.Context, ids ...string) error {
	for _, id := range ids {
		delete(m.store, id)
	}
	return nil
}

// Scan returns records in CVE-id order after afterCVE, like the real repo.
func (m *memRepo) Scan(_ context.Context, afterCVE string, limit int) ([]model.Vulnerability, error) {
	ids := make([]string, 0, len(m.store))
	for id := range m.store {
		if id > afterCVE {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) > limit {
		ids = ids[:limit]
	}
	out := make([]model.Vulnerability, 0, len(ids))
	for _, id := range ids {
		out = append(out, m.store[id])
	}
	return out, nil
}

// memIndex is an in-memory SearchIndex (outbound port) for tests.
type memIndex struct {
	indexed []model.Vulnerability
	extra   []string
	deleted []string
}

func (m *memIndex) Index(_ context.Context, v model.Vulnerability) error {
	m.indexed = append(m.indexed, v)
	return nil
}

func (m *memIndex) Search(context.Context, model.SearchQuery) (model.SearchPage, error) {
	return model.SearchPage{}, nil
}

func (m *memIndex) Ready(context.Context) error { return nil }

// extra holds ids present in the index but never written by the code under
// test — orphans, as far as a reindex is concerned.
func (m *memIndex) IDs(context.Context) ([]string, error) {
	ids := append([]string{}, m.extra...)
	for _, v := range m.indexed {
		ids = append(ids, v.CVEID)
	}
	return ids, nil
}

// Delete records the call and actually removes the document. Recording alone
// made IDs() keep reporting documents the code under test had deleted, which
// is a fake that answers differently from the thing it stands in for.
func (m *memIndex) Delete(_ context.Context, id string) error {
	m.deleted = append(m.deleted, id)

	kept := m.indexed[:0]
	for _, v := range m.indexed {
		if v.CVEID != id {
			kept = append(kept, v)
		}
	}
	m.indexed = kept

	remaining := m.extra[:0]
	for _, e := range m.extra {
		if e != id {
			remaining = append(remaining, e)
		}
	}
	m.extra = remaining
	return nil
}

var _ = Describe("IngestSignal use case", func() {
	ctx := context.Background()

	It("stores a new vulnerability", func() {
		repo := newMemRepo()
		err := commands.NewIngestSignal(repo, &memIndex{}, nil, nil).Handle(ctx, observed(model.Vulnerability{
			CVEID:   "CVE-2021-44228",
			Sources: []string{"nvd"},
		}))
		Expect(err).ToNot(HaveOccurred())

		got, err := repo.GetByID(ctx, "CVE-2021-44228")
		Expect(err).ToNot(HaveOccurred())
		Expect(got.Sources).To(Equal([]string{"nvd"}))
	})

	It("rejects a vulnerability with no CVE id", func() {
		err := commands.NewIngestSignal(newMemRepo(), &memIndex{}, nil, nil).Handle(ctx, observed(model.Vulnerability{}))
		Expect(err).To(MatchError(model.ErrMissingCVEID))
	})

	It("merges a re-observed CVE instead of duplicating (sources unioned)", func() {
		repo := newMemRepo()
		ingest := commands.NewIngestSignal(repo, &memIndex{}, nil, nil)

		Expect(ingest.Handle(ctx, observed(model.Vulnerability{CVEID: "CVE-1", Description: "first", Sources: []string{"nvd"}}))).To(Succeed())
		Expect(ingest.Handle(ctx, observed(model.Vulnerability{CVEID: "CVE-1", Description: "updated", Sources: []string{"cisa_kev"}}))).To(Succeed())

		count, _ := repo.Count(ctx)
		Expect(count).To(Equal(1))

		got, _ := repo.GetByID(ctx, "CVE-1")
		Expect(got.Sources).To(ConsistOf("nvd", "cisa_kev"))
		// The description is chosen by which feed is worth reading, not by
		// which reported last: KEV's entry is a catalog line, NVD's is an
		// analyst paragraph, so the second observation does not displace it.
		Expect(got.Description).To(Equal("first"))
		Expect(got.DescriptionSource).To(Equal("nvd"))
	})

	It("also indexes the stored vulnerability for search", func() {
		repo := newMemRepo()
		index := &memIndex{}

		err := commands.NewIngestSignal(repo, index, nil, nil).Handle(ctx, observed(model.Vulnerability{
			CVEID:   "CVE-2021-44228",
			Sources: []string{"nvd"},
		}))

		Expect(err).ToNot(HaveOccurred())
		Expect(index.indexed).To(HaveLen(1))
		Expect(index.indexed[0].CVEID).To(Equal("CVE-2021-44228"))
	})
})

var _ = Describe("IngestSignal graph linking", func() {
	ctx := context.Background()
	lodash := valueobject.NewPackageRef("npm", "lodash", "< 4.17.21")

	It("links the CVE to the packages the advisory named", func() {
		graph := newMemGraph()

		err := commands.NewIngestSignal(newMemRepo(), &memIndex{}, graph, nil).Handle(ctx, observed(model.Vulnerability{
			CVEID:            "CVE-2021-23337",
			Sources:          []string{"github_advisory"},
			AffectedPackages: []valueobject.PackageRef{lodash},
		}))

		Expect(err).ToNot(HaveOccurred())
		Expect(graph.links).To(HaveKey("CVE-2021-23337"))
		Expect(graph.links["CVE-2021-23337"]).To(HaveLen(1))
	})

	It("does not touch the graph for a finding with no affected packages", func() {
		graph := newMemGraph()

		err := commands.NewIngestSignal(newMemRepo(), &memIndex{}, graph, nil).Handle(ctx, observed(model.Vulnerability{
			CVEID: "CVE-2021-44228", Sources: []string{"nvd"},
		}))

		Expect(err).ToNot(HaveOccurred())
		Expect(graph.links).To(BeEmpty())
	})

	It("stores the record even when the graph is unavailable", func() {
		// The graph is an enrichment; Postgres is the source of truth. A
		// graph outage must never cost us the finding itself.
		graph := newMemGraph()
		graph.writeErr = ports.ErrGraphUnavailable
		repo := newMemRepo()

		err := commands.NewIngestSignal(repo, &memIndex{}, graph, nil).Handle(ctx, observed(model.Vulnerability{
			CVEID:            "CVE-2021-23337",
			Sources:          []string{"github_advisory"},
			AffectedPackages: []valueobject.PackageRef{lodash},
		}))

		Expect(err).ToNot(HaveOccurred())
		count, _ := repo.Count(ctx)
		Expect(count).To(Equal(1))
	})

	It("stores the record even when the graph write fails outright", func() {
		graph := newMemGraph()
		graph.writeErr = errors.New("bolt: connection reset")
		repo := newMemRepo()

		err := commands.NewIngestSignal(repo, &memIndex{}, graph, nil).Handle(ctx, observed(model.Vulnerability{
			CVEID:            "CVE-2021-23337",
			Sources:          []string{"github_advisory"},
			AffectedPackages: []valueobject.PackageRef{lodash},
		}))

		Expect(err).ToNot(HaveOccurred())
		count, _ := repo.Count(ctx)
		Expect(count).To(Equal(1))
	})
})

// countingAlerter records what ingest handed to alert matching.
type countingAlerter struct {
	seen []string
	err  error
}

func (a *countingAlerter) Handle(_ context.Context, v model.Vulnerability) ([]model.Alert, error) {
	a.seen = append(a.seen, v.CVEID)
	return nil, a.err
}

var _ = Describe("IngestSignal alerting", func() {
	ctx := context.Background()

	It("hands every stored record to alert matching", func() {
		alerter := &countingAlerter{}
		err := commands.NewIngestSignal(newMemRepo(), &memIndex{}, nil, alerter).
			Handle(ctx, observed(model.Vulnerability{CVEID: "CVE-2021-44228", Sources: []string{"nvd"}}))

		Expect(err).ToNot(HaveOccurred())
		Expect(alerter.seen).To(ConsistOf("CVE-2021-44228"))
	})

	It("matches against the merged record, not just the incoming fragment", func() {
		// A source that names a package must be able to trigger a rule even
		// when the current observation came from a source that did not.
		repo := newMemRepo()
		alerter := &countingAlerter{}
		ingest := commands.NewIngestSignal(repo, &memIndex{}, nil, alerter)

		Expect(ingest.Handle(ctx, observed(model.Vulnerability{
			CVEID:            "CVE-1",
			Sources:          []string{"github_advisory"},
			AffectedPackages: []valueobject.PackageRef{valueobject.NewPackageRef("npm", "lodash", "")},
		}))).To(Succeed())
		Expect(ingest.Handle(ctx, observed(model.Vulnerability{CVEID: "CVE-1", Sources: []string{"nvd"}}))).To(Succeed())

		stored, err := repo.GetByID(ctx, "CVE-1")
		Expect(err).ToNot(HaveOccurred())
		Expect(stored.AffectedPackages).To(HaveLen(1))
		Expect(alerter.seen).To(HaveLen(2))
	})

	It("stores the record even when alert matching fails", func() {
		repo := newMemRepo()
		alerter := &countingAlerter{err: errors.New("elasticsearch down")}

		err := commands.NewIngestSignal(repo, &memIndex{}, nil, alerter).
			Handle(ctx, observed(model.Vulnerability{CVEID: "CVE-1", Sources: []string{"nvd"}}))

		Expect(err).ToNot(HaveOccurred())
		count, _ := repo.Count(ctx)
		Expect(count).To(Equal(1))
	})
})

// rekeyGraph records the graph writes ingest makes. Methods it does not
// override panic through the nil embedded interface.
type rekeyGraph struct {
	ports.DependencyGraph
	linked  []string
	removed []string
}

func (g *rekeyGraph) LinkVulnerability(_ context.Context, id string, _ []valueobject.PackageRef) error {
	g.linked = append(g.linked, id)
	return nil
}

func (g *rekeyGraph) RemoveVulnerabilities(_ context.Context, ids []string) error {
	g.removed = append(g.removed, ids...)
	return nil
}

var _ = Describe("IngestSignal identity", func() {
	const (
		cve  = "CVE-2021-44228"
		ghsa = "GHSA-jfh8-c2jp-5v3q"
	)
	ctx := context.Background()

	It("files a report under its CVE, findable by its GHSA", func() {
		repo := newMemRepo()
		Expect(commands.NewIngestSignal(repo, &memIndex{}, nil, nil).
			Handle(ctx, observed(model.Vulnerability{CVEID: ghsa, Aliases: []string{cve}}))).To(Succeed())

		got, err := repo.GetByID(ctx, ghsa)
		Expect(err).ToNot(HaveOccurred())
		Expect(got.CVEID).To(Equal(cve))
	})

	It("moves a finding filed under its GHSA onto its CVE once a report links them", func() {
		repo, index, graph := newMemRepo(), &memIndex{}, &rekeyGraph{}
		ingest := commands.NewIngestSignal(repo, index, graph, nil)
		pkgs := []valueobject.PackageRef{valueobject.NewPackageRef("npm", "lodash", "< 4.17.21")}

		Expect(ingest.Handle(ctx, observed(model.Vulnerability{CVEID: ghsa, Title: "Log4Shell", Sources: []string{"github"}, AffectedPackages: pkgs}))).To(Succeed())
		Expect(ingest.Handle(ctx, observed(model.Vulnerability{CVEID: cve, Aliases: []string{ghsa}, Sources: []string{"osv"}}))).To(Succeed())

		Expect(repo.store).To(HaveLen(1))
		got := repo.store[cve]
		Expect(got.Title).To(Equal("Log4Shell"), "nothing the old record knew is lost")
		Expect(got.Sources).To(ConsistOf("github", "osv"))
		Expect(got.AffectedPackages).To(HaveLen(1))
		Expect(index.deleted).To(Equal([]string{ghsa}), "no second search hit under the old id")
		Expect(graph.removed).To(Equal([]string{ghsa}))
		Expect(graph.linked).To(Equal([]string{ghsa, cve}), "the new node keeps the old one's packages")
	})

	It("merges findings that were stored apart once a report shows they are one", func() {
		repo := newMemRepo()
		ingest := commands.NewIngestSignal(repo, &memIndex{}, nil, nil)
		Expect(ingest.Handle(ctx, observed(model.Vulnerability{CVEID: cve, Sources: []string{"nvd"}}))).To(Succeed())
		Expect(ingest.Handle(ctx, observed(model.Vulnerability{CVEID: ghsa, Sources: []string{"github"}}))).To(Succeed())
		Expect(repo.store).To(HaveLen(2))

		Expect(ingest.Handle(ctx, observed(model.Vulnerability{CVEID: "PYSEC-2021-1", Aliases: []string{cve, ghsa}, Sources: []string{"osv"}}))).To(Succeed())

		Expect(repo.store).To(HaveLen(1))
		Expect(repo.store[cve].Sources).To(ConsistOf("nvd", "github", "osv"))
		Expect(repo.store[cve].Aliases).To(Equal([]string{ghsa, "PYSEC-2021-1"}))
	})

	It("keeps a finding flagged as malware when a later feed does not say so", func() {
		repo := newMemRepo()
		ingest := commands.NewIngestSignal(repo, &memIndex{}, nil, nil)
		Expect(ingest.Handle(ctx, observed(model.Vulnerability{CVEID: "GHSA-fw8c-xr5c-95f9", Kind: model.KindMalware}))).To(Succeed())
		Expect(ingest.Handle(ctx, observed(model.Vulnerability{CVEID: "GHSA-fw8c-xr5c-95f9", Title: "axios"}))).To(Succeed())

		Expect(repo.store["GHSA-fw8c-xr5c-95f9"].IsMalware()).To(BeTrue())
	})

	It("retries a write that raced another worker", func() {
		repo := newMemRepo()
		repo.conflict = 1
		Expect(commands.NewIngestSignal(repo, &memIndex{}, nil, nil).Handle(ctx, observed(model.Vulnerability{CVEID: cve}))).To(Succeed())
		Expect(repo.upserts).To(Equal(2))
		Expect(repo.store).To(HaveKey(cve))
	})

	It("gives up when the conflict does not clear", func() {
		repo := newMemRepo()
		repo.conflict = 100
		err := commands.NewIngestSignal(repo, &memIndex{}, nil, nil).Handle(ctx, observed(model.Vulnerability{CVEID: cve}))
		Expect(err).To(MatchError(ports.ErrConflict))
		Expect(repo.upserts).To(Equal(3))
	})
})

var _ = Describe("IngestSignal and replayed history", func() {
	ctx := context.Background()

	It("stores a historical observation exactly as it stores a current one", func() {
		repo := newMemRepo()
		err := commands.NewIngestSignal(repo, &memIndex{}, nil, nil).Handle(ctx, commands.Observation{
			Vulnerability: model.Vulnerability{CVEID: "CVE-2017-5638", Sources: []string{"nvd"}},
			Historical:    true,
		})
		Expect(err).ToNot(HaveOccurred())

		// A backfill publishes the same events polling would, which is exactly
		// what lets a backfilled record and a polled one merge into each other.
		stored, err := repo.GetByID(ctx, "CVE-2017-5638")
		Expect(err).ToNot(HaveOccurred())
		Expect(stored.CVEID).To(Equal("CVE-2017-5638"))
	})

	It("tells nobody about a historical observation", func() {
		alerter := &countingAlerter{}

		err := commands.NewIngestSignal(newMemRepo(), &memIndex{}, nil, alerter).Handle(ctx,
			commands.Observation{
				Vulnerability: model.Vulnerability{CVEID: "CVE-2017-5638", Sources: []string{"nvd"}},
				Historical:    true,
			})

		Expect(err).ToNot(HaveOccurred())
		// Loading ten years of advisories is not ten years of news: a
		// subscription matching them would fire thousands of times for things
		// fixed long ago.
		Expect(alerter.seen).To(BeEmpty())
	})

	It("still alerts on an ordinary observation of the same finding", func() {
		alerter := &countingAlerter{}

		err := commands.NewIngestSignal(newMemRepo(), &memIndex{}, nil, alerter).Handle(ctx,
			observed(model.Vulnerability{CVEID: "CVE-2017-5638", Sources: []string{"nvd"}}))

		Expect(err).ToNot(HaveOccurred())
		Expect(alerter.seen).To(ConsistOf("CVE-2017-5638"))
	})
})

var _ = Describe("IngestSignal and retracted findings", func() {
	ctx := context.Background()

	It("does not store a finding the source has retracted", func() {
		repo := newMemRepo()

		err := commands.NewIngestSignal(repo, &memIndex{}, nil, nil).Handle(ctx, commands.Observation{
			Vulnerability: model.Vulnerability{
				CVEID:       "CVE-2022-35253",
				Description: "Rejected reason: DO NOT USE THIS CANDIDATE NUMBER.",
				Sources:     []string{"nvd"},
			},
			Withdrawn: true,
		})

		Expect(err).ToNot(HaveOccurred())
		count, _ := repo.Count(ctx)
		Expect(count).To(BeZero())
	})

	It("removes one that was stored before it was retracted", func() {
		repo := newMemRepo()
		ingest := commands.NewIngestSignal(repo, &memIndex{}, nil, nil)
		stored := model.Vulnerability{CVEID: "CVE-2022-35253", Description: "a real finding", Sources: []string{"nvd"}}

		Expect(ingest.Handle(ctx, observed(stored))).To(Succeed())
		count, _ := repo.Count(ctx)
		Expect(count).To(Equal(1))

		// A CVE is often rejected after it was published and stored, which is
		// why the retraction is published rather than silently skipped.
		Expect(ingest.Handle(ctx, commands.Observation{Vulnerability: stored, Withdrawn: true})).To(Succeed())

		count, _ = repo.Count(ctx)
		Expect(count).To(BeZero())
	})

	It("takes the search document with it", func() {
		repo := newMemRepo()
		index := &memIndex{}
		ingest := commands.NewIngestSignal(repo, index, nil, nil)
		stored := model.Vulnerability{CVEID: "CVE-2022-35253", Sources: []string{"nvd"}}

		Expect(ingest.Handle(ctx, observed(stored))).To(Succeed())
		Expect(ingest.Handle(ctx, commands.Observation{Vulnerability: stored, Withdrawn: true})).To(Succeed())

		ids, err := index.IDs(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(ids).ToNot(ContainElement("CVE-2022-35253"))
	})

	It("stores the id again if it is ever published properly", func() {
		repo := newMemRepo()
		ingest := commands.NewIngestSignal(repo, &memIndex{}, nil, nil)
		id := model.Vulnerability{CVEID: "CVE-2022-35253", Sources: []string{"nvd"}}

		Expect(ingest.Handle(ctx, commands.Observation{Vulnerability: id, Withdrawn: true})).To(Succeed())
		// Withdrawing removes the record; it does not blacklist the id.
		Expect(ingest.Handle(ctx, observed(id))).To(Succeed())

		count, _ := repo.Count(ctx)
		Expect(count).To(Equal(1))
	})
})

var _ = Describe("recognising a retraction in a stored record", func() {
	DescribeTable("says whether a description marks the finding as disowned",
		func(description string, retracted bool) {
			Expect(commands.IsRetracted(model.Vulnerability{Description: description})).To(Equal(retracted))
		},
		Entry("NVD's current wording", "Rejected reason: DO NOT USE THIS CANDIDATE NUMBER.", true),
		Entry("NVD's older marker", "** REJECT ** DO NOT USE THIS CANDIDATE NUMBER.", true),
		Entry("an ordinary advisory", "A flaw in log4j allows remote code execution.", false),
		Entry("no description at all", "", false),
	)
})
