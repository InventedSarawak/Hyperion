package tui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// Update handles one message. Keys are dispatched by mode first: while the
// query is being edited every printable key belongs to the query, not to the
// application's shortcuts.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case tickMsg:
		// Skip a beat rather than stacking requests on a slow backend.
		if m.loading {
			return m, m.tick()
		}
		m.loading = true
		return m, tea.Batch(m.refresh(), m.tick())

	case feedMsg:
		m.loading = false
		m.err = msg.err
		if msg.err == nil {
			m.feed = msg.feed
			m.feed.UpdatedAt = time.Now()
			m.lastRefresh = m.feed.UpdatedAt
			if m.cursor >= len(m.feed.Hits) {
				m.cursor = max(0, len(m.feed.Hits)-1)
			}
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
		return m, m.refresh()
	case tea.KeyEsc:
		m.editing = false
		m.query = m.feed.Query // discard the edit
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

	case "j", "down":
		if m.tab == TabFeed && m.cursor < len(m.feed.Hits)-1 {
			m.cursor++
		}
		return m, nil
	case "k", "up":
		if m.tab == TabFeed && m.cursor > 0 {
			m.cursor--
		}
		return m, nil
	case "g":
		m.cursor = 0
		return m, nil
	case "G":
		m.cursor = max(0, len(m.feed.Hits)-1)
		return m, nil

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
		return m, m.explore(selected.CVEID)

	case "/":
		m.editing = true
		return m, nil

	case "r":
		m.loading = true
		if m.tab == TabGraph {
			if selected, ok := m.Selected(); ok {
				return m, m.explore(selected.CVEID)
			}
		}
		return m, m.refresh()
	}
	return m, nil
}
