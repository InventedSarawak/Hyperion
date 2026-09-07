package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
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
		b.WriteString(m.feedRow(hit.Vulnerability, i == m.cursor) + "\n")
	}
	return b.String()
}

// Column widths, in terminal cells. The id column fits a GHSA identifier
// (19 cells), which is longer than a CVE id — sizing it to the CVE would make
// every GHSA row shunt the columns to its right.
const (
	colMarker   = 2
	colID       = 19
	colSeverity = 9
)

// feedRow renders one row. Selected and unselected rows are laid out by the
// same code on purpose: when the two were built separately they drifted, and a
// row that measured correctly in one path wrapped in the other.
func (m Model) feedRow(v model.Vulnerability, selected bool) string {
	severity := v.SeverityLabel()
	id := pad(truncate(v.CVEID, colID), colID)
	sev := pad(severity, colSeverity)
	headline := truncate(v.Headline(), m.headlineWidth())

	if selected {
		return styleSelected.Render("▸ " + id + " " + sev + " " + headline)
	}
	return "  " + styleCVE.Render(id) + " " +
		severityStyle(severity).Render(sev) + " " + headline
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
	chrome := colMarker + colID + 1 + colSeverity + 1
	if m.width <= chrome+10 {
		return 60
	}
	return m.width - chrome
}

// truncate shortens s to at most width terminal cells, marking the cut with an
// ellipsis. Width is measured in cells rather than runes because they are not
// the same thing: a CJK character occupies two columns, so counting runes would
// let a row overflow the terminal and wrap.
func truncate(s string, width int) string {
	if width <= 1 || runewidth.StringWidth(s) <= width {
		return s
	}
	return runewidth.Truncate(s, width, "…")
}

// pad right-pads s to exactly width cells, so columns line up whatever the
// content is. A value already at or over the width is returned unchanged.
func pad(s string, width int) string {
	if gap := width - runewidth.StringWidth(s); gap > 0 {
		return s + strings.Repeat(" ", gap)
	}
	return s
}
