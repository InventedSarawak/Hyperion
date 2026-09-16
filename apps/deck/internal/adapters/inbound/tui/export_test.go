package tui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// SpinnerTick builds the internal spinner message, so specs can advance the
// animation without the message type leaving the package.
func SpinnerTick() tea.Msg { return spinnerMsg(time.Now()) }

// PollTick builds the internal poll message, so specs can fire a refresh
// without waiting out the real interval.
func PollTick() tea.Msg { return tickMsg(time.Now()) }

// LoadedIDs exposes the loaded rows, for asserting on list length.
func (m Model) LoadedIDs() []string {
	ids := make([]string, 0, len(m.feed.Hits))
	for _, h := range m.feed.Hits {
		ids = append(ids, h.Vulnerability.CVEID)
	}
	return ids
}
