package elasticsearch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The search index is addressed through an alias that points at one concrete
// index, rather than by writing to an index of that name directly.
//
// It costs nothing to read through an alias and it is the only way to change a
// mapping without downtime. Field types cannot be changed in place, so the
// alternative is deleting the index and rebuilding it — during which search
// returns nothing, on a corpus that takes minutes to rewrite. With an alias the
// new index is built alongside the old one and the alias is moved in a single
// atomic step: readers see the old index until the instant they see the new.
//
// Concrete indices are numbered, so "which one is live" is a fact about the
// cluster rather than something to remember.
func concreteIndex(alias string, generation int) string {
	return fmt.Sprintf("%s-%06d", alias, generation)
}

// aliasState describes how the name is currently resolved.
type aliasState struct {
	// alias is true when the name is an alias, which is the intended shape.
	alias bool
	// legacy is true when the name is a concrete index — how every index
	// created before this existed is shaped. Usable, but not swappable.
	legacy bool
	// current is the concrete index the alias points at.
	current string
	// generation is the number in that index's name.
	generation int
}

// resolveAlias asks the cluster what the name currently is.
func (i *Index) resolveAlias(ctx context.Context) (aliasState, error) {
	resp, err := i.do(ctx, http.MethodGet, "/_alias/"+i.name, nil)
	if err != nil {
		return aliasState{}, fmt.Errorf("elasticsearch: resolve alias: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var aliased map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&aliased); err != nil {
			return aliasState{}, fmt.Errorf("elasticsearch: resolve alias: %w", err)
		}
		for name := range aliased {
			return aliasState{alias: true, current: name, generation: generationOf(i.name, name)}, nil
		}
		return aliasState{}, fmt.Errorf("elasticsearch: alias %s points at nothing", i.name)
	}

	// Not an alias. It may still be an index of that name, from before there
	// was an alias.
	head, err := i.do(ctx, http.MethodHead, "/"+i.name, nil)
	if err != nil {
		return aliasState{}, fmt.Errorf("elasticsearch: head index: %w", err)
	}
	head.Body.Close()
	if head.StatusCode == http.StatusOK {
		return aliasState{legacy: true, current: i.name}, nil
	}
	return aliasState{}, nil // nothing exists yet
}

// generationOf reads the number out of a concrete index name, or 0.
func generationOf(alias, concrete string) int {
	suffix := strings.TrimPrefix(concrete, alias+"-")
	n, err := strconv.Atoi(suffix)
	if err != nil {
		return 0
	}
	return n
}

// Swap rebuilds the index under a fresh mapping and moves the alias onto it.
//
// The rebuild happens server-side, from the current index rather than from
// Postgres: Elasticsearch copies documents far faster than cortex can re-read
// and re-send them, and the documents are already exactly what is wanted. What
// this cannot fix is a mapping change that needs data cortex never indexed —
// for that, `-reindex` rebuilds from the store of record instead.
//
// The alias moves in one request, so there is no moment when it points at
// neither index or at both.
func (i *Index) Swap(ctx context.Context) (from, to string, err error) {
	state, err := i.resolveAlias(ctx)
	if err != nil {
		return "", "", err
	}
	if state.current == "" {
		return "", "", fmt.Errorf("elasticsearch: nothing to swap: %s does not exist", i.name)
	}

	next := concreteIndex(i.name, state.generation+1)
	if err := i.createIndex(ctx, next); err != nil {
		return "", "", err
	}
	if err := i.buildInto(ctx, state.current, next); err != nil {
		// Take the half-built index away again. Leaving it would make the
		// next attempt collide with its own leftovers, and it is worse than
		// useless: a partial copy nothing points at.
		if cleanup := i.deleteIndex(context.WithoutCancel(ctx), next); cleanup != nil {
			return "", "", fmt.Errorf("%w (and %s could not be removed: %w)", err, next, cleanup)
		}
		return "", "", err
	}

	// One request: remove the old, add the new, and for a legacy index delete
	// it — a name cannot be both an index and an alias, so the old index has
	// to be gone before the alias can take its name.
	if state.legacy {
		if err := i.deleteIndex(ctx, state.current); err != nil {
			return "", "", err
		}
		if err := i.updateAliases(ctx, `{"actions":[{"add":{"index":"`+next+`","alias":"`+i.name+`"}}]}`); err != nil {
			return "", "", err
		}
		return state.current, next, nil
	}

	actions := `{"actions":[` +
		`{"remove":{"index":"` + state.current + `","alias":"` + i.name + `"}},` +
		`{"add":{"index":"` + next + `","alias":"` + i.name + `"}}]}`
	if err := i.updateAliases(ctx, actions); err != nil {
		return "", "", err
	}
	if err := i.deleteIndex(ctx, state.current); err != nil {
		return state.current, next, fmt.Errorf("elasticsearch: alias moved but the old index remains: %w", err)
	}
	return state.current, next, nil
}

// createIndex creates one concrete index with the current mapping.
func (i *Index) createIndex(ctx context.Context, name string) error {
	resp, err := i.do(ctx, http.MethodPut, "/"+name, strings.NewReader(indexMapping))
	if err != nil {
		return fmt.Errorf("elasticsearch: create index %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("elasticsearch: create index %s status %d: %s",
			name, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// buildInto copies the documents across and makes them searchable.
//
// Refreshed at both ends, for two different reasons. The source, because a
// reindex copies what is searchable and a document written a moment ago is not
// yet — anything written just before the swap would otherwise be lost. The
// destination, because moving the alias onto an index that has not been
// refreshed would point readers at one that answers nothing.
func (i *Index) buildInto(ctx context.Context, from, to string) error {
	// Refresh the source first. A reindex copies what is *searchable*, and a
	// document written a moment ago is not yet — so without this, every write
	// from the last second before a swap is silently left behind.
	if err := i.refresh(ctx, from); err != nil {
		return err
	}
	if err := i.reindexInto(ctx, from, to); err != nil {
		return err
	}
	return i.refresh(ctx, to)
}

// refresh makes everything written to an index visible to search.
func (i *Index) refresh(ctx context.Context, name string) error {
	resp, err := i.do(ctx, http.MethodPost, "/"+name+"/_refresh", nil)
	if err != nil {
		return fmt.Errorf("elasticsearch: refresh %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("elasticsearch: refresh %s status %d: %s",
			name, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// reindexInto copies every document from one index to another.
//
// Started as a task rather than held open on one request: copying half a
// million documents takes longer than any sensible HTTP timeout, and a client
// that gives up while the server is still working learns nothing and leaves the
// work running. Elasticsearch hands back a task id; this waits on that.
func (i *Index) reindexInto(ctx context.Context, from, to string) error {
	body := `{"source":{"index":"` + from + `"},"dest":{"index":"` + to + `"}}`
	resp, err := i.do(ctx, http.MethodPost, "/_reindex?wait_for_completion=false", strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("elasticsearch: reindex %s -> %s: %w", from, to, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("elasticsearch: reindex %s -> %s status %d: %s",
			from, to, resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var started struct {
		Task string `json:"task"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&started); err != nil {
		return fmt.Errorf("elasticsearch: reindex %s -> %s: %w", from, to, err)
	}
	if started.Task == "" {
		return fmt.Errorf("elasticsearch: reindex %s -> %s: no task id returned", from, to)
	}
	return i.awaitReindex(ctx, started.Task, from, to)
}

// reindexPoll is how often the copy is checked on. Long enough not to badger
// the cluster while it is doing the actual work.
const reindexPoll = 2 * time.Second

// awaitReindex waits for a reindex task and reports what it did.
func (i *Index) awaitReindex(ctx context.Context, task, from, to string) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(reindexPoll):
		}

		resp, err := i.do(ctx, http.MethodGet, "/_tasks/"+task, nil)
		if err != nil {
			return fmt.Errorf("elasticsearch: reindex %s -> %s: %w", from, to, err)
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("elasticsearch: reindex %s -> %s: %w", from, to, readErr)
		}

		var status struct {
			Completed bool `json:"completed"`
			Response  struct {
				Total    int `json:"total"`
				Created  int `json:"created"`
				Failures []struct {
					ID    string `json:"id"`
					Cause struct {
						Type   string `json:"type"`
						Reason string `json:"reason"`
					} `json:"cause"`
				} `json:"failures"`
			} `json:"response"`
		}
		if err := json.Unmarshal(raw, &status); err != nil {
			return fmt.Errorf("elasticsearch: reindex %s -> %s: %w", from, to, err)
		}
		if !status.Completed {
			continue
		}

		// Failures are what make it a failure, whatever the status: moving the
		// alias onto a partial copy would lose documents silently.
		if n := len(status.Response.Failures); n > 0 {
			first := status.Response.Failures[0]
			return fmt.Errorf("elasticsearch: reindex %s -> %s: %d of %d documents failed; first was %s: %s: %s",
				from, to, n, status.Response.Total, first.ID, first.Cause.Type, first.Cause.Reason)
		}
		if status.Response.Total > 0 && status.Response.Created < status.Response.Total {
			return fmt.Errorf("elasticsearch: reindex %s -> %s copied %d of %d documents",
				from, to, status.Response.Created, status.Response.Total)
		}
		return nil
	}
}

// updateAliases applies alias actions atomically.
func (i *Index) updateAliases(ctx context.Context, actions string) error {
	resp, err := i.do(ctx, http.MethodPost, "/_aliases", strings.NewReader(actions))
	if err != nil {
		return fmt.Errorf("elasticsearch: update aliases: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("elasticsearch: update aliases status %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// deleteIndex removes one concrete index.
func (i *Index) deleteIndex(ctx context.Context, name string) error {
	resp, err := i.do(ctx, http.MethodDelete, "/"+name, nil)
	if err != nil {
		return fmt.Errorf("elasticsearch: delete index %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("elasticsearch: delete index %s status %d: %s",
			name, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}
