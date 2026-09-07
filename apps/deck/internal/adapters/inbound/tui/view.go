package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// Column widths, in terminal cells. The id column fits a GHSA identifier
// (19 cells), which is longer than a CVE id — sizing it to the CVE would make
// every GHSA row shunt the columns to its right.
const (
	colMarker   = 2
	colID       = 19
	colSeverity = 9
)

// View renders the whole screen: banner, tabs, the active view, the prompt,
// and the key hints.
func (m Model) View() string {
	if m.quitting {
		return ""
	}

	var b strings.Builder

	// The splash only shows until the first result arrives: it is an
	// introduction, not furniture to scroll past on every refresh.
	if m.showBanner() {
		b.WriteString(banner(m.width) + "\n\n")
	}

	b.WriteString(m.header())
	b.WriteString("\n\n")

	if m.tab == TabGraph {
		b.WriteString(m.graphView())
	} else {
		b.WriteString(m.feedView())
	}

	b.WriteString("\n")
	b.WriteString(m.promptBox())
	b.WriteString("\n")
	b.WriteString(m.footer())
	return b.String()
}

// showBanner reports whether the splash logo is still worth the vertical
// space: before any data has arrived, and only in a tall enough terminal.
func (m Model) showBanner() bool {
	if m.height > 0 && m.height < 24 {
		return false
	}
	return len(m.feed.Hits) == 0 && m.err == nil
}

func (m Model) header() string {
	tabs := make([]string, 0, 2)
	for _, t := range []Tab{TabFeed, TabGraph} {
		label := fmt.Sprintf(" %d %s ", int(t)+1, t.Title())
		if t == m.tab {
			tabs = append(tabs, styleTabOn.Render("▌"+label))
			continue
		}
		tabs = append(tabs, styleTabOff.Render(" "+label))
	}

	status := styleDim.Render("connected to " + m.opts.Endpoint)
	switch {
	case m.loading:
		status = styleSelect.Render(spinnerFrame(m.spinner)) + styleDim.Render(" working…")
	case !m.lastRefresh.IsZero():
		status = styleDim.Render("updated " + m.lastRefresh.Format("15:04:05"))
	}

	left := styleBrand.Render("HYPERION") + "  " + strings.Join(tabs, "")
	return m.spread(left, status)
}

// spread pushes right to the right-hand edge when the width is known.
func (m Model) spread(left, right string) string {
	gap := m.width - lipgloss.Width(left) - lipgloss.Width(right) - 1
	if m.width <= 0 || gap < 1 {
		return left + "  " + right
	}
	return left + strings.Repeat(" ", gap) + right
}

func (m Model) feedView() string {
	if err := m.err; err != nil {
		return panel("Error", styleError.Render(err.Error()), m.width)
	}

	title := fmt.Sprintf("Findings  %s",
		styleCounter.Render(fmt.Sprintf("query %q — %d findings", m.query, len(m.feed.Hits))))

	if len(m.feed.Hits) == 0 {
		body := styleDim.Render("no findings — press / to change the query")
		if m.loading {
			body = styleDim.Render(spinnerFrame(m.spinner) + " loading…")
		}
		return panel(title, body, m.width)
	}

	rows := make([]string, 0, len(m.feed.Hits))
	for i, hit := range m.feed.Hits {
		rows = append(rows, m.feedRow(hit.Vulnerability, i == m.cursor))
	}
	return panel(title, strings.Join(rows, "\n"), m.width)
}

// feedRow renders one row. Selected and unselected rows are laid out by the
// same code on purpose: when the two were built separately they drifted, and a
// row that measured correctly in one path wrapped in the other.
func (m Model) feedRow(v model.Vulnerability, selected bool) string {
	severity := v.SeverityLabel()
	id := pad(truncate(v.CVEID, colID), colID)
	sev := pad(severity, colSeverity)
	headline := truncate(v.Headline(), m.headlineWidth())

	if selected {
		return styleSelect.Render("▸ " + id + " " + sev + " " + headline)
	}
	return "  " + styleCVE.Render(id) + " " +
		severityStyle(severity).Render(sev) + " " + headline
}

func (m Model) graphView() string {
	if err := m.err; err != nil {
		return panel("Error", styleError.Render(err.Error()), m.width)
	}
	if m.loading && m.radius.CVEID == "" {
		return panel("Graph Explorer", styleDim.Render(spinnerFrame(m.spinner)+" loading…"), m.width)
	}
	if m.radius.CVEID == "" {
		return panel("Graph Explorer",
			styleDim.Render("select a finding in the Live Feed and press enter"), m.width)
	}

	summary := fmt.Sprintf("%d repositories exposed via %d vulnerable package(s)",
		len(m.radius.Repositories), len(m.radius.VulnerablePackages))
	if !m.radius.Linked() {
		summary = "this CVE is not linked to any package yet"
	}

	body := styleDim.Render(summary) + "\n\n" + styleTree.Render(RenderTree(m.radius))
	return panel("Blast Radius  "+styleCounter.Render(m.radius.CVEID), body, m.width)
}

// promptBox is the search input, styled after a shell prompt: always visible,
// so it is obvious the query is editable, and focused when the user presses /.
func (m Model) promptBox() string {
	// Sized exactly like panel() so the prompt lines up with the box above it.
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colFaint).
		Padding(0, 1)
	if m.width > 4 {
		box = box.Width(m.width - 2)
	}

	if m.editing {
		box = box.BorderForeground(colAccent)
		return box.Render(stylePrompt.Render("search: ") + m.query + styleSelect.Render("▏"))
	}
	return box.Render(styleFaint.Render("search: ") + styleDim.Render(m.query))
}

func (m Model) footer() string {
	if m.editing {
		return styleFaint.Render("  enter search · esc cancel")
	}
	return styleFaint.Render(
		"  ↑/↓ move · enter blast radius · tab switch · / search · r refresh · q quit")
}

// headlineWidth keeps a long summary from wrapping the row. It falls back to a
// sane width before the terminal has reported its size.
func (m Model) headlineWidth() int {
	// Panel border and padding cost 4 cells on top of the columns.
	chrome := colMarker + colID + 1 + colSeverity + 1 + 4
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
