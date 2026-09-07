package tui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// SpinnerTick builds the internal spinner message, so specs can advance the
// animation without the message type leaving the package.
func SpinnerTick() tea.Msg { return spinnerMsg(time.Now()) }
