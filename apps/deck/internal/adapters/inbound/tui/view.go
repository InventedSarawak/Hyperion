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

	// The banner is pinned: it stays for the whole session. It is the list
	// below it that scrolls, sized so the frame never outgrows the terminal.
	if m.showBanner() {
		b.WriteString(banner() + "\n\n")
	}

	b.WriteString(m.header())
	b.WriteString("\n\n")

	switch m.tab {
	case TabDetails:
		b.WriteString(m.detailsView())
	case TabGraph:
		b.WriteString(m.graphView())
	case TabRepos:
		b.WriteString(m.reposView())
	default:
		b.WriteString(m.feedView())
	}

	b.WriteString("\n")
	b.WriteString(m.promptBox())
	b.WriteString("\n")
	b.WriteString(m.footer())
	return b.String()
}

func (m Model) header() string {
	tabs := make([]string, 0, len(allTabs))
	for _, t := range allTabs {
		label := fmt.Sprintf(" %d %s ", int(t)+1, t.Title())
		if t == m.tab {
			tabs = append(tabs, styleTabOn.Render("▌"+label))
			continue
		}
		tabs = append(tabs, styleTabOff.Render(" "+label))
	}

	status := styleDim.Render("connected to " + m.opts.Endpoint)
	switch {
	case m.busy():
		status = styleSelect.Render(spinnerFrame(m.spinner)) + styleDim.Render(" working…")
	case !m.lastRefresh.IsZero():
		status = styleDim.Render("updated " + m.lastRefresh.Format("15:04:05"))
	}

	left := styleBrand.Render("HYPERION") + "  " + strings.Join(tabs, "")
	if m.width <= 0 || lipgloss.Width(left)+2+lipgloss.Width(status) <= m.width {
		return m.spread(left, status)
	}
	// Too narrow for everything: the status goes first, then the tabs
	// shorten. A header that wraps pushes the whole frame down a line.
	if lipgloss.Width(left) <= m.width {
		return left
	}
	compact := styleBrand.Render("HYPERION") + " " + m.compactTabs()
	if lipgloss.Width(compact) <= m.width {
		return compact
	}
	return styleBrand.Render(truncate("HYPERION", m.width))
}

// compactTabs is the tab bar for a narrow terminal. At the narrowest only
// the active tab keeps its name; the rest shrink to their number.
func (m Model) compactTabs() string {
	render := func(named bool) string {
		parts := make([]string, 0, len(allTabs))
		for _, t := range allTabs {
			label := fmt.Sprintf("%d", int(t)+1)
			if named || t == m.tab {
				label += " " + t.Short()
			}
			if t == m.tab {
				parts = append(parts, styleTabOn.Render("▌"+label))
			} else {
				parts = append(parts, styleTabOff.Render(label))
			}
		}
		return strings.Join(parts, " ")
	}
	if full := render(true); m.width <= 0 || lipgloss.Width(full)+10 <= m.width {
		return full
	}
	return render(false)
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

	loaded := len(m.feed.Hits)
	start, end := window(m.offset, m.bodyRows(), loaded)
	title := m.fit("Findings  " + m.feedCounter(start, end))

	if loaded == 0 {
		body := styleDim.Render("no findings — press / to change the query")
		if m.loading {
			body = styleDim.Render(spinnerFrame(m.spinner) + " loading…")
		}
		return panel(title, body, m.width)
	}

	rows := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		rows = append(rows, m.feedRow(m.feed.Hits[i].Vulnerability, i == m.cursor))
	}
	return panel(title, strings.Join(rows, "\n"), m.width)
}

// feedCounter says what the list is, how much of it is loaded out of how much
// exists, which part is on screen, and whether more is coming:
//
//	latest findings — 50 of 6,771  ·  27–50  ·  ↓ more
//	query "next" · best match — 25 of 187  ·  loading more…
func (m Model) feedCounter(start, end int) string {
	loaded := len(m.feed.Hits)

	what := "latest findings"
	if m.active != "" {
		what = fmt.Sprintf("query %q · %s", m.active, m.sort.Label())
	}
	if m.malware {
		what += " · incl. malware"
	}

	counter := fmt.Sprintf("%s — %d", what, loaded)
	switch {
	case m.feed.Total > 0 && m.feed.TotalIsLowerBound:
		counter += " of " + thousands(m.feed.Total) + "+"
	case m.feed.Total > 0:
		counter += " of " + thousands(m.feed.Total)
	default:
		counter += " findings"
	}

	if end-start < loaded {
		// Only say where we are when there is somewhere else to be.
		counter += fmt.Sprintf("  ·  %d–%d", start+1, end)
	}
	switch {
	case m.loadingMore:
		counter += "  ·  " + spinnerFrame(m.spinner) + " loading more…"
	case m.moreErr != nil:
		counter += "  ·  couldn't load more (n to retry)"
	case m.feed.HasMore() && end == loaded:
		counter += "  ·  ↓ more"
	}
	return counter
}

// thousands renders 6771 as "6,771".
func thousands(n int64) string {
	digits := fmt.Sprintf("%d", n)
	var b strings.Builder
	for i, d := range digits {
		if i > 0 && (len(digits)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(d)
	}
	return b.String()
}

// feedRow renders one row. Selected and unselected rows are laid out by the
// same code on purpose: when the two were built separately they drifted, and a
// row that measured correctly in one path wrapped in the other.
func (m Model) feedRow(v model.Vulnerability, selected bool) string {
	severity := v.SeverityLabel()
	if v.IsMalware() {
		// Not a severity, but it outranks every one: say what it is.
		severity = labelMalware
	}

	// Narrower than the fixed columns: a plain row, truncated. Legibility
	// beats colour, and a row that wraps costs two lines of the budget.
	if m.innerWidth() < fixedColumns {
		row := truncate(v.CVEID+" "+severity, m.innerWidth()-colMarker)
		if selected {
			return styleSelect.Render("▸ " + row)
		}
		return "  " + row
	}

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
	if m.radius.CVEID == "" {
		return panel("Graph Explorer",
			styleDim.Render("select a finding in the Live Feed and press b (or enter, then enter again)"), m.width)
	}
	if err := m.radiusErr; err != nil {
		return panel(m.fit("Blast Radius  "+m.radius.CVEID), styleError.Render(m.fit(err.Error())), m.width)
	}
	if m.radiusLoading {
		return panel(m.fit("Blast Radius  "+m.radius.CVEID),
			styleDim.Render(spinnerFrame(m.spinner)+" walking the dependency graph…"), m.width)
	}

	// Reaching a library is not the same as being exposed to its flaw: count
	// the repositories whose declared versions rule it out separately.
	exposed, ruledOut := 0, 0
	for _, r := range m.radius.Repositories {
		if r.Verdict == model.VerdictNotAffected {
			ruledOut++
		} else {
			exposed++
		}
	}
	pkgs := len(m.radius.VulnerablePackages)
	summary := fmt.Sprintf("%d %s exposed via %d vulnerable %s",
		exposed, plural(exposed, "repository", "repositories"), pkgs, plural(pkgs, "package", "packages"))
	if ruledOut > 0 {
		summary += fmt.Sprintf("  ·  %d ruled out by version", ruledOut)
	}
	switch {
	case !m.radius.Linked():
		summary = "this CVE is not linked to any package yet"
	case len(m.radius.Repositories) == 0:
		summary = "no tracked repository reaches the affected packages — add repositories in tab 4"
	}

	lines := m.treeLines()
	start, end := window(m.graphOffset, m.treeRows(), len(lines))

	visible := make([]string, 0, end-start)
	for _, line := range lines[start:end] {
		// A chain like "repo → lib → lib → lib" can outrun the panel, and a
		// wrapped line is a line the height budget never counted.
		visible = append(visible, truncate(line, m.innerWidth()))
	}

	title := "Blast Radius  " + m.radius.CVEID
	if end-start < len(lines) {
		title += fmt.Sprintf("  ·  lines %d–%d of %d", start+1, end, len(lines))
	}

	body := styleDim.Render(m.fit(summary)) + "\n\n" + styleTree.Render(strings.Join(visible, "\n"))
	return panel(m.fit(title), body, m.width)
}

// promptBox is the input line, styled after a shell prompt: always visible,
// so it is obvious it is editable. It is the search box everywhere except the
// Repositories tab, where it is where an owner is typed to add from.
func (m Model) promptBox() string {
	// Sized exactly like panel() so the prompt lines up with the box above it.
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colFaint).
		Padding(0, 1)
	if m.width > 4 {
		box = box.Width(m.width - 2)
	}

	if m.tab == TabRepos && m.opts.Repositories != nil {
		const label = "add from github user or org: "
		owner := truncateLeft(m.repos.owner, m.innerWidth()-len(label)-1)
		if m.repos.mode == repoOwnerPrompt {
			box = box.BorderForeground(colAccent)
			return box.Render(stylePrompt.Render(label) + owner + styleSelect.Render("▏"))
		}
		hint := "press a"
		if m.repos.pickOwner != "" && m.repos.mode == repoPicker {
			hint = m.repos.pickOwner
		}
		return box.Render(styleFaint.Render(label) + styleDim.Render(truncate(hint, m.innerWidth()-len(label))))
	}

	// "search: " and the caret take 9 cells; a query longer than the rest
	// would wrap the box onto a fourth line the budget never counted.
	query := truncateLeft(m.query, m.innerWidth()-9)
	if m.editing {
		box = box.BorderForeground(colAccent)
		return box.Render(stylePrompt.Render("search: ") + query + styleSelect.Render("▏"))
	}
	if query == "" {
		return box.Render(styleFaint.Render("search: ") + styleFaint.Render("none — showing the latest (press / to search)"))
	}
	return box.Render(styleFaint.Render("search: ") + styleDim.Render(query))
}

func (m Model) footer() string {
	var hints string
	switch {
	case m.editing:
		hints = "  enter search · esc cancel"
	case m.tab == TabDetails:
		hints = "  ↑/↓ scroll · enter/b blast radius · esc back · tab switch · r reload · q quit"
	case m.tab == TabGraph:
		hints = "  ↑/↓ scroll · pgup/pgdn page · esc back · tab switch · r refresh · q quit"
	case m.tab == TabRepos:
		hints = m.repoHints()
	default:
		hints = "  ↑/↓ move · enter details · b blast radius · n more · s sort · m malware · / search · tab switch · r refresh · q quit"
	}
	return styleFaint.Render(m.fitPlain(hints))
}

func (m Model) repoHints() string {
	switch m.repos.mode {
	case repoOwnerPrompt:
		return "  enter list repositories · esc cancel"
	case repoPicker:
		return "  ↑/↓ move · space select · a select all · enter track selected · esc cancel"
	case repoConfirmRemove:
		return "  y remove · n keep"
	case repoFindings:
		return "  ↑/↓ move · enter details · b blast radius · u show/hide ruled out · r refresh · esc back · q quit"
	}
	return "  ↑/↓ move · enter findings · a add · d remove · s rescan · r refresh · tab switch · q quit"
}

// fixedColumns is the marker, id and severity columns with their gaps.
const fixedColumns = colMarker + colID + 1 + colSeverity + 1

// headlineWidth is what is left of the panel after the fixed columns. Before
// the terminal has reported its size it falls back to a sane default; after,
// it is exact — even when that leaves nothing — because a headline that does
// not fit wraps the row onto a second line.
func (m Model) headlineWidth() int {
	if m.width <= 0 {
		return 60
	}
	return m.innerWidth() - fixedColumns
}

// truncate shortens s to at most width terminal cells, marking the cut with an
// ellipsis. Width is measured in cells rather than runes because they are not
// the same thing: a CJK character occupies two columns, so counting runes would
// let a row overflow the terminal and wrap. A width of zero or less yields
// nothing — returning s unchanged there would be the overflow this prevents.
func truncate(s string, width int) string {
	switch {
	case runewidth.StringWidth(s) <= width:
		return s
	case width <= 0:
		return ""
	case width == 1:
		return "…"
	default:
		return runewidth.Truncate(s, width, "…")
	}
}

// pad right-pads s to exactly width cells, so columns line up whatever the
// content is. A value already at or over the width is returned unchanged.
func pad(s string, width int) string {
	if gap := width - runewidth.StringWidth(s); gap > 0 {
		return s + strings.Repeat(" ", gap)
	}
	return s
}

// fit truncates a panel title to the panel's inner width; panel() styles it.
func (m Model) fit(title string) string {
	return truncate(title, m.innerWidth())
}

// fitPlain truncates a line to the terminal width without styling it.
func (m Model) fitPlain(line string) string {
	if m.width <= 0 {
		return line
	}
	return truncate(line, m.width)
}

// truncateLeft keeps the end of s, which for a query being typed is the part
// the user is looking at.
func truncateLeft(s string, width int) string {
	if width <= 1 || runewidth.StringWidth(s) <= width {
		return s
	}
	runes := []rune(s)
	for i := range runes {
		if tail := string(runes[i:]); runewidth.StringWidth(tail) <= width-1 {
			return "…" + tail
		}
	}
	return "…"
}
