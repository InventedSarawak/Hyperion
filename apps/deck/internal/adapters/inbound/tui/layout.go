package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// The vertical budget.
//
// Bubble Tea keeps only the *last* terminal-height lines of a frame that is too
// tall (standard_renderer.go: newLines[len(newLines)-r.height:]). An
// overflowing list therefore does not scroll: it silently pushes the banner and
// the tab bar off the top of the screen. So every line drawn outside the
// scrollable body is counted here, and the body gets exactly what is left.
const (
	// bannerHeight is the six-line logo plus the blank line beneath it.
	bannerHeight = 6 + 1
	// chromeHeight is everything else outside the body: the tab bar and the
	// blank line after it (2), the panel's top border, title and bottom border
	// (3), the prompt box (3), and the key hints (1).
	chromeHeight = 2 + 3 + 3 + 1
	// minBodyRows is the least list worth showing. Below it the banner gives
	// way, because the logo is decoration and the findings are the point.
	minBodyRows = 8
	// graphHeaderRows is the summary line and blank line above the tree.
	graphHeaderRows = 2
)

// unbounded stands in for "no limit" before the terminal has reported its size.
const unbounded = 1 << 30

// Update handles one message, then keeps both scroll positions inside what is
// on screen. Clamping after every message, rather than in each key handler,
// means a resize, a shorter refresh or a new blast radius can never strand the
// cursor off screen.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	next, cmd := m.update(msg)
	if model, ok := next.(Model); ok {
		return model.clampScroll(), cmd
	}
	return next, cmd
}

// showBanner reports whether the logo fits alongside a usable list. It stays
// for the life of the session, and only yields in a terminal too small to hold
// it without crowding out the findings.
func (m Model) showBanner() bool {
	if m.width > 0 && m.width < bannerWidth+4 {
		return false
	}
	if m.height > 0 && m.height < chromeHeight+bannerHeight+minBodyRows {
		return false
	}
	return true
}

// bodyRows is how many lines the active panel's body may use.
func (m Model) bodyRows() int {
	if m.height <= 0 {
		return unbounded
	}
	rows := m.height - chromeHeight
	if m.showBanner() {
		rows -= bannerHeight
	}
	return max(1, rows)
}

// treeRows is how many lines of the blast-radius tree fit under its summary.
func (m Model) treeRows() int {
	return max(1, m.bodyRows()-graphHeaderRows)
}

// innerWidth is the space inside a panel: its width minus border and padding.
// A line wider than this wraps, and a wrapped line is an extra line the budget
// above did not count.
func (m Model) innerWidth() int {
	if m.width <= 0 {
		return unbounded
	}
	return max(1, m.width-4)
}

// treeLines splits the rendered blast radius into display lines.
func (m Model) treeLines() []string {
	if m.radius.CVEID == "" {
		return nil
	}
	return strings.Split(strings.TrimRight(RenderTree(m.radius), "\n"), "\n")
}

// clampScroll keeps the cursor on screen and both offsets in range.
func (m Model) clampScroll() Model {
	rows := m.bodyRows()
	total := len(m.feed.Hits)

	m.cursor = clamp(m.cursor, 0, max(0, total-1))
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+rows {
		m.offset = m.cursor - rows + 1
	}
	m.offset = clamp(m.offset, 0, max(0, total-rows))

	m.graphOffset = clamp(m.graphOffset, 0, max(0, len(m.treeLines())-m.treeRows()))
	if m.tab == TabDetails {
		m.detailOffset = clamp(m.detailOffset, 0, max(0, len(m.detailLines())-rows))
	}

	m.repos.cursor, m.repos.offset = follow(m.repos.cursor, m.repos.offset, len(m.repos.list), m.repoRows())
	m.repos.pickCursor, m.repos.pickOffset = follow(m.repos.pickCursor, m.repos.pickOffset, len(m.repos.discovered), m.repoRows())
	return m
}

// follow keeps a cursor within n items and the window of rows around it.
func follow(cursor, offset, n, rows int) (int, int) {
	cursor = clamp(cursor, 0, max(0, n-1))
	if cursor < offset {
		offset = cursor
	}
	if cursor >= offset+rows {
		offset = cursor - rows + 1
	}
	return cursor, clamp(offset, 0, max(0, n-rows))
}

// repoRows is how many repositories fit in the Repositories panel: the body
// less the column header and, when there is one, the notice line above it.
func (m Model) repoRows() int {
	rows := m.bodyRows() - 1
	if m.repoNotice() != "" {
		rows--
	}
	return max(1, rows)
}

// window returns the [start, end) slice of n items that fits in rows.
func window(offset, rows, n int) (int, int) {
	start := clamp(offset, 0, n)
	return start, min(n, start+rows)
}

func clamp(v, lo, hi int) int {
	if hi < lo {
		return lo
	}
	return max(lo, min(v, hi))
}
