package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Styles. Colours are ANSI-256 so the UI degrades gracefully over SSH and in
// terminals without truecolor.
var (
	styleTitle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15"))
	styleTabOn    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("0")).Background(lipgloss.Color("39")).Padding(0, 1)
	styleTabOff   = lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Padding(0, 1)
	styleDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	styleError    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("203"))
	styleSelected = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	styleCVE      = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))
	styleTree     = lipgloss.NewStyle().Foreground(lipgloss.Color("109"))
)

// severityStyle colours a rating by how much it should alarm the reader.
func severityStyle(label string) lipgloss.Style {
	switch label {
	case "CRITICAL":
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("199"))
	case "HIGH":
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("203"))
	case "MEDIUM":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	case "LOW":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("35"))
	default:
		return styleDim
	}
}

// View renders the whole screen: header, body for the active tab, footer.
func (m Model) View() string {
	if m.quitting {
		return ""
	}

	var b strings.Builder
	b.WriteString(m.header())
	b.WriteString("\n\n")

	if m.tab == TabGraph {
		b.WriteString(m.graphView())
	} else {
		b.WriteString(m.feedView())
	}

	b.WriteString("\n")
	b.WriteString(m.footer())
	return b.String()
}

func (m Model) header() string {
	tabs := make([]string, 0, 2)
	for _, t := range []Tab{TabFeed, TabGraph} {
		label := fmt.Sprintf("%d %s", int(t)+1, t.Title())
		if t == m.tab {
			tabs = append(tabs, styleTabOn.Render(label))
			continue
		}
		tabs = append(tabs, styleTabOff.Render(label))
	}

	status := styleDim.Render("connected to " + m.opts.CortexAddr)
	if m.loading {
		status = styleDim.Render("refreshing…")
	}
	if !m.lastRefresh.IsZero() && !m.loading {
		status = styleDim.Render("updated " + m.lastRefresh.Format("15:04:05"))
	}

	return styleTitle.Render("HYPERION") + "  " + strings.Join(tabs, " ") + "  " + status
}

func (m Model) feedView() string {
	var b strings.Builder

	if m.editing {
		b.WriteString(styleSelected.Render("search: ") + m.query + "▊\n\n")
	} else {
		b.WriteString(styleDim.Render(fmt.Sprintf("query %q — %d findings", m.query, len(m.feed.Hits))) + "\n\n")
	}

	if err := m.err; err != nil {
		b.WriteString(styleError.Render("error: "+err.Error()) + "\n")
		return b.String()
	}
	if len(m.feed.Hits) == 0 {
		if m.loading {
			return b.String() + styleDim.Render("loading…") + "\n"
		}
		return b.String() + styleDim.Render("no findings — press / to change the query") + "\n"
	}

	for i, hit := range m.feed.Hits {
		v := hit.Vulnerability
		severity := v.SeverityLabel()

		marker := "  "
		line := fmt.Sprintf("%-18s %-9s %s", v.CVEID, severity, truncate(v.Headline(), m.headlineWidth()))
		if i == m.cursor {
			marker = styleSelected.Render("▸ ")
			line = styleSelected.Render(line)
		} else {
			line = styleCVE.Render(fmt.Sprintf("%-18s ", v.CVEID)) +
				severityStyle(severity).Render(fmt.Sprintf("%-9s ", severity)) +
				truncate(v.Headline(), m.headlineWidth())
		}
		b.WriteString(marker + line + "\n")
	}
	return b.String()
}

func (m Model) graphView() string {
	if err := m.err; err != nil {
		return styleError.Render("error: "+err.Error()) + "\n"
	}
	if m.loading && m.radius.CVEID == "" {
		return styleDim.Render("loading…") + "\n"
	}
	if m.radius.CVEID == "" {
		return styleDim.Render("select a finding in the Live Feed and press enter") + "\n"
	}

	summary := styleDim.Render(fmt.Sprintf("%d repositories exposed via %d vulnerable package(s)",
		len(m.radius.Repositories), len(m.radius.VulnerablePackages)))
	if !m.radius.Linked() {
		summary = styleDim.Render("this CVE is not linked to any package yet")
	}

	return summary + "\n\n" + styleTree.Render(RenderTree(m.radius))
}

func (m Model) footer() string {
	if m.editing {
		return styleDim.Render("enter search · esc cancel")
	}
	keys := "↑/↓ move · enter blast radius · tab switch · / search · r refresh · q quit"
	return styleDim.Render(keys)
}

// headlineWidth keeps a long summary from wrapping the row. It falls back to a
// sane width before the terminal has reported its size.
func (m Model) headlineWidth() int {
	const chrome = 34 // marker + cve column + severity column
	if m.width <= chrome+10 {
		return 60
	}
	return m.width - chrome
}

// truncate shortens s to at most width runes, marking the cut with an ellipsis.
func truncate(s string, width int) string {
	runes := []rune(s)
	if width <= 1 || len(runes) <= width {
		return s
	}
	return string(runes[:width-1]) + "…"
}
