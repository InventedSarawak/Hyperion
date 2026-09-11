package tui

import (
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// update handles one message; Update (layout.go) wraps it to keep scrolling in
// range. Keys are dispatched by mode first: while the query is being edited
// every printable key belongs to the query, not to the application's shortcuts.
func (m Model) update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case spinnerMsg:
		if !m.loading && !m.loadingMore {
			return m, nil // stop animating; a new request re-arms it
		}
		m.spinner++
		return m, m.spin()

	case tickMsg:
		// Skip a beat rather than stacking requests on a slow backend, or
		// replacing the list underneath a page that is still arriving.
		if m.loading || m.loadingMore {
			return m, m.tick()
		}
		m.loading = true
		return m, tea.Batch(m.refresh(), m.tick(), m.spin())

	case feedMsg:
		m.loading = false
		m.err = msg.err
		if msg.err == nil {
			m.feed = msg.feed
			m.feed.UpdatedAt = time.Now()
			m.lastRefresh = m.feed.UpdatedAt
			m.sort = m.feed.Sort // the use case may have settled it
			// A new list: any page still in flight belongs to the old one.
			m.generation++
			m.loadingMore = false
			m.moreErr = nil
			// Newer findings arriving at the top would otherwise slide a
			// different row under a cursor that stayed put.
			if msg.keep != "" {
				if i := m.feed.IndexOf(msg.keep); i >= 0 {
					m.cursor = i
				}
			}
		}
		return m, nil

	case moreMsg:
		if msg.generation != m.generation {
			// Fetched for a list that has since been replaced. Leave
			// loadingMore alone: a request for the current list may be in
			// flight, and this stale reply says nothing about it.
			return m, nil
		}
		m.loadingMore = false
		// A failed page must not cost the rows already loaded, so it is
		// reported alongside the list rather than in place of it.
		m.moreErr = msg.err
		if msg.err == nil {
			m.feed = msg.feed
		}
		return m, nil

	case radiusMsg:
		m.loading = false
		m.err = msg.err
		if msg.err == nil {
			m.radius = msg.radius
		}
		return m, nil

	case tea.KeyMsg:
		if m.editing {
			return m.updateEditing(msg)
		}
		return m.updateBrowsing(msg)
	}
	return m, nil
}

// updateEditing handles keys while the query is being typed.
func (m Model) updateEditing(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter:
		m.editing = false
		m.loading = true
		m.active = strings.TrimSpace(m.query)
		// A search term is asking for the best match; clearing it goes back
		// to the live feed. Either way it is a new list, so start at the top.
		m.sort = model.SortRelevance
		if m.active == "" {
			m.sort = model.SortNewest
		}
		m.cursor, m.offset = 0, 0
		return m, tea.Batch(m.fresh(), m.spin())
	case tea.KeyEsc:
		m.editing = false
		m.query = m.active // discard the edit
		return m, nil
	case tea.KeyBackspace:
		if runes := []rune(m.query); len(runes) > 0 {
			m.query = string(runes[:len(runes)-1])
		}
		return m, nil
	case tea.KeyCtrlC:
		m.quitting = true
		return m, tea.Quit
	case tea.KeyRunes, tea.KeySpace:
		m.query += string(msg.Runes)
		if msg.Type == tea.KeySpace {
			m.query += " "
		}
		return m, nil
	}
	return m, nil
}

// updateBrowsing handles keys while navigating.
func (m Model) updateBrowsing(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit

	case "tab":
		m.tab = 1 - m.tab
		return m, nil
	case "1":
		m.tab = TabFeed
		return m, nil
	case "2":
		m.tab = TabGraph
		return m, nil

	// Movement moves the cursor in the feed and scrolls the tree in the graph
	// explorer. Nothing here bounds-checks: clampScroll does, after every
	// message, so the limits live in one place.
	case "j", "down":
		m = m.scroll(1)
		return m.loadMoreIfAtEnd()
	case "k", "up":
		m = m.scroll(-1)
		return m, nil
	case "pgdown", "ctrl+d":
		m = m.scroll(max(1, m.bodyRows()-1))
		return m.loadMoreIfAtEnd()
	case "pgup", "ctrl+u":
		m = m.scroll(-max(1, m.bodyRows()-1))
		return m, nil
	case "g", "home":
		m = m.scroll(-unbounded)
		return m, nil
	case "G", "end":
		m = m.scroll(unbounded)
		return m.loadMoreIfAtEnd()

	case "n", "]":
		if m.tab != TabFeed || m.loadingMore || !m.feed.HasMore() {
			return m, nil
		}
		m.loadingMore = true
		return m, tea.Batch(m.more(), m.spin())

	case "s":
		// Best match and newest are both meaningful for a search term. With
		// no term there is only one order — newest — so there is nothing to
		// toggle.
		if m.tab != TabFeed || m.active == "" {
			return m, nil
		}
		if m.sort == model.SortNewest {
			m.sort = model.SortRelevance
		} else {
			m.sort = model.SortNewest
		}
		m.loading = true
		m.cursor, m.offset = 0, 0
		return m, tea.Batch(m.fresh(), m.spin())

	case "enter":
		// Opening the graph for the selected finding is the whole point of
		// having the two views side by side.
		selected, ok := m.Selected()
		if !ok {
			return m, nil
		}
		m.tab = TabGraph
		m.loading = true
		// Clear the previous result so the view never shows one CVE's
		// radius under another CVE's heading while the query is in flight.
		m.radius = model.BlastRadius{CVEID: selected.CVEID}
		m.graphOffset = 0
		return m, tea.Batch(m.explore(selected.CVEID), m.spin())

	case "/":
		m.editing = true
		return m, nil

	case "r":
		m.loading = true
		if m.tab == TabGraph {
			if selected, ok := m.Selected(); ok {
				return m, tea.Batch(m.explore(selected.CVEID), m.spin())
			}
		}
		return m, tea.Batch(m.refresh(), m.spin())
	}
	return m, nil
}

// scroll moves by delta in whichever list the active tab shows.
func (m Model) scroll(delta int) Model {
	if m.tab == TabGraph {
		m.graphOffset = saturatingAdd(m.graphOffset, delta)
		return m
	}
	m.cursor = saturatingAdd(m.cursor, delta)
	return m
}

// saturatingAdd adds without overflowing when delta is ±unbounded.
func saturatingAdd(v, delta int) int {
	switch {
	case delta >= unbounded:
		return unbounded
	case delta <= -unbounded:
		return 0
	default:
		return v + delta
	}
}

// loadMoreIfAtEnd fetches the next page when the cursor reaches the last
// loaded row, so scrolling simply keeps going instead of stopping at a wall.
func (m Model) loadMoreIfAtEnd() (tea.Model, tea.Cmd) {
	if m.tab != TabFeed || m.loading || m.loadingMore || !m.feed.HasMore() {
		return m, nil
	}
	if m.cursor < len(m.feed.Hits)-1 {
		return m, nil
	}
	m.loadingMore = true
	return m, tea.Batch(m.more(), m.spin())
}
