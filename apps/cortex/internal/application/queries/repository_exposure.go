package queries

import (
	"context"
	"errors"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// FindingsReader loads findings by any of their ids (consumer-side
// interface, implemented by the vulnerability repo).
type FindingsReader interface {
	FindByIDs(ctx context.Context, ids []string) ([]model.Vulnerability, error)
}

// ErrNeedRepository is returned when no repository is named.
var ErrNeedRepository = errors.New("enter a repository as owner/name")

// RepositoryExposure answers "which vulnerabilities does this repository
// have?" — blast radius read from the repository's side — and judges each by
// comparing the version the repository declares with the versions the
// advisory says are affected. That judgement is what turns "depends on a
// library that once had a bug" into "is exposed to it".
type RepositoryExposure struct {
	graph        ports.DependencyGraph
	findings     FindingsReader
	defaultDepth int
}

// NewRepositoryExposure wires the use case. defaultDepth <= 0 falls back to
// the blast-radius default, so both directions walk the same distance.
func NewRepositoryExposure(graph ports.DependencyGraph, findings FindingsReader, defaultDepth int) *RepositoryExposure {
	if defaultDepth <= 0 || defaultDepth > MaxBlastRadiusDepth {
		defaultDepth = DefaultBlastRadiusDepth
	}
	return &RepositoryExposure{graph: graph, findings: findings, defaultDepth: defaultDepth}
}

// Handle lists one repository's findings, worst first. Findings its declared
// versions rule out are dropped unless includeUnaffected is set; the summary
// is computed before that filter either way.
func (q *RepositoryExposure) Handle(ctx context.Context, fullName string, maxDepth int, includeUnaffected bool) (model.RepositoryExposure, error) {
	fullName = strings.TrimSpace(fullName)
	if fullName == "" {
		return model.RepositoryExposure{}, ErrNeedRepository
	}
	if q.graph == nil {
		return model.RepositoryExposure{}, ports.ErrGraphUnavailable
	}
	depth := maxDepth
	if depth <= 0 || depth > MaxBlastRadiusDepth {
		depth = q.defaultDepth
	}

	rows, err := q.graph.FindRepositoryExposures(ctx, []string{fullName}, depth)
	if err != nil {
		return model.RepositoryExposure{}, err
	}
	out := model.RepositoryExposure{FullName: fullName, Scanned: len(rows) > 0}
	if len(rows) > 0 {
		out.FullName = rows[0].Repository // the graph's spelling
	} else if out.Scanned, err = q.graph.HasRepository(ctx, fullName); err != nil {
		return model.RepositoryExposure{}, err
	}

	judged, err := q.judge(ctx, rows)
	if err != nil {
		return model.RepositoryExposure{}, err
	}
	out.Summary = model.Summarize(judged)
	for _, e := range judged {
		if includeUnaffected || e.Verdict.Exposed() {
			out.Findings = append(out.Findings, e)
		}
	}
	model.SortExposures(out.Findings)
	return out, nil
}

// Summaries flags every repository in the graph, keyed by lower-cased full
// name, for the watchlist. A repository with nothing reachable is absent.
func (q *RepositoryExposure) Summaries(ctx context.Context) (map[string]model.ExposureSummary, error) {
	if q.graph == nil {
		return nil, ports.ErrGraphUnavailable
	}
	rows, err := q.graph.FindRepositoryExposures(ctx, nil, q.defaultDepth)
	if err != nil {
		return nil, err
	}
	judged, err := q.judge(ctx, rows)
	if err != nil {
		return nil, err
	}
	byRepo := map[string][]model.Exposure{}
	for _, e := range judged {
		key := strings.ToLower(e.Repository)
		byRepo[key] = append(byRepo[key], e)
	}
	out := make(map[string]model.ExposureSummary, len(byRepo))
	for key, es := range byRepo {
		out[key] = model.Summarize(es)
	}
	return out, nil
}

// judge fills in each row's finding from the store of record, for its
// severity and title, and its verdict from the versions.
func (q *RepositoryExposure) judge(ctx context.Context, rows []model.Exposure) ([]model.Exposure, error) {
	if len(rows) == 0 {
		return nil, nil
	}
	if q.findings != nil {
		seen := map[string]struct{}{}
		var ids []string
		for _, r := range rows {
			if _, ok := seen[r.Finding.CVEID]; !ok {
				seen[r.Finding.CVEID] = struct{}{}
				ids = append(ids, r.Finding.CVEID)
			}
		}
		found, err := q.findings.FindByIDs(ctx, ids)
		if err != nil {
			return nil, err
		}
		byID := make(map[string]model.Vulnerability, len(found))
		for _, v := range found {
			for _, id := range v.IDs() {
				byID[id] = v
			}
		}
		for i := range rows {
			if v, ok := byID[rows[i].Finding.CVEID]; ok {
				rows[i].Finding = v
			}
		}
	}
	for i := range rows {
		rows[i].Verdict = valueobject.JudgeExposure(rows[i].Package.Ecosystem, rows[i].Package.Version, rows[i].AffectedVersions)
	}
	return rows, nil
}
