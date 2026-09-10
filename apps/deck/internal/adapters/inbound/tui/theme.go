package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// The palette. ANSI-256 rather than truecolor so the UI degrades gracefully
// over SSH and in terminals that do not advertise 24-bit colour.
var (
	colAccent = lipgloss.Color("39")  // the one bright colour: selection, focus
	colMuted  = lipgloss.Color("245") // secondary text
	colFaint  = lipgloss.Color("240") // borders and rules
	colText   = lipgloss.Color("252")
	colAlarm  = lipgloss.Color("203")
)

var (
	styleBrand   = lipgloss.NewStyle().Bold(true).Foreground(colAccent)
	styleTitle   = lipgloss.NewStyle().Bold(true).Foreground(colText)
	styleDim     = lipgloss.NewStyle().Foreground(colMuted)
	styleFaint   = lipgloss.NewStyle().Foreground(colFaint)
	styleError   = lipgloss.NewStyle().Bold(true).Foreground(colAlarm)
	styleSelect  = lipgloss.NewStyle().Bold(true).Foreground(colAccent)
	styleCVE     = lipgloss.NewStyle().Foreground(colAccent)
	styleTree    = lipgloss.NewStyle().Foreground(lipgloss.Color("109"))
	styleTabOn   = lipgloss.NewStyle().Bold(true).Foreground(colAccent)
	styleTabOff  = lipgloss.NewStyle().Foreground(colMuted)
	stylePrompt  = lipgloss.NewStyle().Bold(true).Foreground(colAccent)
	styleCounter = lipgloss.NewStyle().Foreground(colMuted)
)

// severityStyle colours a rating by how much it should alarm the reader.
func severityStyle(label string) lipgloss.Style {
	switch label {
	case "CRITICAL":
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("199"))
	case "HIGH":
		return lipgloss.NewStyle().Bold(true).Foreground(colAlarm)
	case "MEDIUM":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	case "LOW":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("35"))
	default:
		return styleDim
	}
}

// banner is the logo pinned to the top of the screen. It is 64 columns wide,
// so showBanner only draws it when the terminal can hold it without wrapping —
// a wrapped banner looks broken, and looking broken is worse than none. The tab
// bar always carries the name, so a narrow terminal still says HYPERION.
const bannerWidth = 64

var bannerLines = []string{
	`██╗  ██╗██╗   ██╗██████╗ ███████╗██████╗ ██╗ ██████╗ ███╗   ██╗`,
	`██║  ██║╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██║██╔═══██╗████╗  ██║`,
	`███████║ ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║██║   ██║██╔██╗ ██║`,
	`██╔══██║  ╚██╔╝  ██╔═══╝ ██╔══╝  ██╔══██╗██║██║   ██║██║╚██╗██║`,
	`██║  ██║   ██║   ██║     ███████╗██║  ██║██║╚██████╔╝██║ ╚████║`,
	`╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝`,
}

// banner renders the logo.
func banner() string {
	return styleBrand.Render(strings.Join(bannerLines, "\n"))
}

// spinnerFrames are braille dots — one cell wide in every terminal that can
// show them, so the line they sit on never changes width as they animate.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func spinnerFrame(tick int) string {
	if len(spinnerFrames) == 0 {
		return ""
	}
	return spinnerFrames[tick%len(spinnerFrames)]
}

// panel wraps content in a rounded box with a title in the top border.
func panel(title, content string, width int) string {
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colFaint).
		Padding(0, 1)
	if width > 4 {
		box = box.Width(width - 2)
	}
	if title != "" {
		content = styleTitle.Render(title) + "\n" + content
	}
	return box.Render(content)
}
