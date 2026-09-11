package tui

import (
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// update handles one message; Update (layout.go) wraps it to keep scrolling in
// range. Keys are dispatched by mode first: while text is being typed — a
// search, or an owner to add repositories from — every printable key belongs
// to the text, not to the application's shortcuts.
func (m Model) update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case spinnerMsg:
		if !m.busy() {
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
		if msg.cveID != m.radius.CVEID {
			return m, nil // a traversal for a finding no longer open
		}
		m.radiusLoading = false
		m.radiusErr = msg.err
		if msg.err == nil {
			m.radius = msg.radius
			if m.radius.CVEID == "" {
				m.radius.CVEID = msg.cveID
			}
		}
		return m, nil

	case detailMsg:
		if msg.id != m.detail.CVEID {
			return m, nil
		}
		m.detailLoading = false
		m.detailErr = msg.err
		if msg.err == nil && msg.v.CVEID != "" {
			m.detail = msg.v
		}
		return m, nil

	case reposMsg, reposPollMsg, discoverMsg, trackMsg, untrackMsg:
		return m.updateRepoMsg(msg)

	case tea.KeyMsg:
		switch {
		case m.editing:
			return m.updateEditing(msg)
		case m.typingOwner():
			return m.updateOwnerPrompt(msg)
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
		m.tab = TabFeed
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

// switchTo shows a tab, loading what it needs the first time it is shown.
func (m Model) switchTo(t Tab) (tea.Model, tea.Cmd) {
	m.tab = t
	if t == TabRepos {
		return m.enterRepos()
	}
	return m, nil
}

// updateBrowsing handles keys while navigating.
func (m Model) updateBrowsing(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// The Repositories tab has keys of its own (a, d, space…), and while it
	// is in the middle of something — picking, confirming — they come first.
	if m.tab == TabRepos {
		if next, cmd, handled := m.updateRepoKeys(msg); handled {
			return next, cmd
		}
	}

	switch msg.String() {
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit

	case "tab":
		return m.switchTo((m.tab + 1) % Tab(len(allTabs)))
	case "shift+tab":
		return m.switchTo((m.tab + Tab(len(allTabs)) - 1) % Tab(len(allTabs)))
	case "1":
		return m.switchTo(TabFeed)
	case "2":
		return m.switchTo(TabDetails)
	case "3":
		return m.switchTo(TabGraph)
	case "4":
		return m.switchTo(TabRepos)

	case "esc":
		// Back out of a finding to the list it came from.
		if m.tab == TabDetails || m.tab == TabGraph {
			m.tab = TabFeed
		}
		return m, nil

	// Movement moves the cursor in the feed and scrolls the details and the
	// tree. Nothing here bounds-checks: clampScroll does, after every
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
		switch m.tab {
		case TabFeed:
			// Reading the finding comes first; its blast radius loads
			// alongside, one keypress away.
			selected, ok := m.Selected()
			if !ok {
				return m, nil
			}
			return m.open(selected)
		case TabDetails:
			return m.showGraph()
		}
		return m, nil

	case "b":
		// Straight to the blast radius. From the feed that opens the finding
		// too, so Details and the graph always describe the same one.
		if m.tab == TabFeed {
			selected, ok := m.Selected()
			if !ok {
				return m, nil
			}
			if selected.CVEID != m.detail.CVEID {
				opened, cmd := m.open(selected)
				opened.tab = TabGraph
				return opened, cmd
			}
		}
		return m.showGraph()

	case "/":
		m.editing = true
		return m, nil

	case "r":
		switch m.tab {
		case TabGraph:
			if id, ok := m.graphTarget(); ok {
				next, cmd := m.startRadius(id)
				return next, tea.Batch(cmd, next.spin())
			}
			return m, nil
		case TabDetails:
			if m.detail.CVEID != "" && m.opts.Details != nil {
				m.detailLoading = true
				return m, tea.Batch(m.loadDetail(m.detail.CVEID), m.spin())
			}
			return m, nil
		}
		m.loading = true
		return m, tea.Batch(m.refresh(), m.spin())
	}
	return m, nil
}

// showGraph opens the Graph Explorer for the current finding, starting a
// traversal unless one for that finding is already loaded or in flight.
func (m Model) showGraph() (tea.Model, tea.Cmd) {
	id, ok := m.graphTarget()
	if !ok {
		return m, nil
	}
	m.tab = TabGraph
	// Already loaded, or on its way: nothing to fetch. A failed one is retried.
	if m.radius.CVEID == id && (m.radiusLoading || m.radiusErr == nil) {
		return m, nil
	}
	next, cmd := m.startRadius(id)
	return next, tea.Batch(cmd, next.spin())
}

// scroll moves by delta in whichever list the active tab shows.
func (m Model) scroll(delta int) Model {
	switch m.tab {
	case TabGraph:
		m.graphOffset = saturatingAdd(m.graphOffset, delta)
	case TabDetails:
		m.detailOffset = saturatingAdd(m.detailOffset, delta)
	default:
		m.cursor = saturatingAdd(m.cursor, delta)
	}
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
