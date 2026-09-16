package tui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
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

// StreamedFinding builds the internal message that says a finding arrived on
// the live feed, so specs can exercise the debounce without a broker.
func StreamedFinding(id string) tea.Msg {
	return streamMsg{v: model.Vulnerability{CVEID: id}}
}

// StreamRefreshDue builds the internal message that fires when a debounced,
// stream-triggered refresh is due.
func StreamRefreshDue() tea.Msg { return streamRefreshMsg(time.Now()) }

// StreamEnded builds the internal message that says the live feed closed.
func StreamEnded() tea.Msg { return streamEndedMsg{} }

// Live reports whether the model believes the live feed is connected.
func (m Model) Live() bool { return m.liveOn }

// StreamRefreshPending reports whether a stream-triggered refresh is already
// scheduled, which is what stops a burst becoming a query per finding.
func (m Model) StreamRefreshPending() bool { return m.livePending }
