package tui_test

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mattn/go-runewidth"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/adapters/inbound/tui"
	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// stubSearch and stubExplorer stand in for the use cases, so the whole TUI can
// be driven without a terminal or a running backend.
// stubSearch pages through feed.Hits the way the gateway does: the page
// token is the offset of the next page.
type stubSearch struct {
	gotQuery  string
	gotSort   model.SearchSort
	gotSize   int
	feed      model.Feed // the complete result set
	err       error
	moreErr   error
	moreCalls int
}

func (s *stubSearch) Handle(_ context.Context, query string, sort model.SearchSort, size int) (model.Feed, error) {
	s.gotQuery, s.gotSort, s.gotSize = query, sort, size
	if s.err != nil {
		return model.Feed{}, s.err
	}
	return model.Feed{Query: query, Sort: sort}.Append(s.page(0, size)), nil
}

func (s *stubSearch) More(_ context.Context, feed model.Feed, size int) (model.Feed, error) {
	s.moreCalls++
	if s.moreErr != nil {
		return feed, s.moreErr
	}
	offset, _ := strconv.Atoi(feed.NextPageToken)
	return feed.Append(s.page(offset, size)), nil
}

func (s *stubSearch) page(offset, size int) model.SearchPage {
	all := s.feed.Hits
	offset = min(offset, len(all))
	end := min(len(all), offset+size)
	page := model.SearchPage{Hits: all[offset:end], Total: int64(len(all))}
	if end < len(all) {
		page.NextPageToken = strconv.Itoa(end)
	}
	return page
}

type stubExplorer struct {
	gotCVE string
	radius model.BlastRadius
	err    error
}

func (s *stubExplorer) Handle(_ context.Context, cveID string, _ int) (model.BlastRadius, error) {
	s.gotCVE = cveID
	return s.radius, s.err
}

// ansiPattern matches the escape sequences lipgloss emits, so specs can assert
// on the text a user actually sees.
var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func stripANSI(s string) string { return ansiPattern.ReplaceAllString(s, "") }

// column reports the terminal column where substr starts. It measures display
// cells rather than bytes: the selected row is marked with "▸", three bytes for
// one column, so a byte offset would compare two different things.
func column(line, substr string) int {
	GinkgoHelper()
	at := strings.Index(line, substr)
	Expect(at).To(BeNumerically(">=", 0), "%q not found in %q", substr, line)
	return runewidth.StringWidth(line[:at])
}

// key builds a keypress message.
func key(s string) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)} }

// apply runs a message through the model and returns the concrete model back.
func apply(m tui.Model, msg tea.Msg) (tui.Model, tea.Cmd) {
	GinkgoHelper()
	next, cmd := m.Update(msg)
	typed, ok := next.(tui.Model)
	Expect(ok).To(BeTrue())
	return typed, cmd
}

// runCmd executes a command and returns its message, giving up on commands
// that do not answer quickly. The model batches its data fetches together with
// long timers (the 30s poll), and a test must not sit out a real timer to see
// the fetch's result.
func runCmd(cmd tea.Cmd) tea.Msg {
	if cmd == nil {
		return nil
	}
	done := make(chan tea.Msg, 1)
	go func() { done <- cmd() }()
	select {
	case msg := <-done:
		return msg
	case <-time.After(250 * time.Millisecond):
		return nil
	}
}

// deliver runs a command and applies every message it yields, flattening the
// batches the model returns.
func deliver(m tui.Model, cmd tea.Cmd) tui.Model {
	GinkgoHelper()
	msg := runCmd(cmd)
	if batch, ok := msg.(tea.BatchMsg); ok {
		for _, inner := range batch {
			m = deliver(m, inner)
		}
		return m
	}
	if msg == nil {
		return m
	}
	m, _ = apply(m, msg)
	return m
}

// feedWith builds a feed of the given CVE ids.
func feedWith(ids ...string) model.Feed {
	feed := model.Feed{}
	for _, id := range ids {
		feed.Hits = append(feed.Hits, model.SearchHit{
			Vulnerability: model.Vulnerability{
				CVEID:  id,
				Title:  "finding " + id,
				Scores: []model.CVSS{{BaseScore: 9.8, Severity: "CRITICAL"}},
			},
		})
	}
	return feed
}

var _ = Describe("TUI model", func() {
	var (
		search   *stubSearch
		explorer *stubExplorer
		m        tui.Model
	)

	BeforeEach(func() {
		search = &stubSearch{feed: feedWith("CVE-2021-44228", "CVE-2021-23337")}
		explorer = &stubExplorer{}
		m = tui.New(search, explorer, tui.Options{Query: "cve", PageSize: 25, Endpoint: "nexus http://localhost:8080/graphql"})
	})

	// loaded returns the model after a successful first refresh. Init batches
	// the refresh with the poll timer, so the refresh is triggered here the
	// same way the "r" key does it, then its result is fed back in.
	loaded := func() tui.Model {
		GinkgoHelper()
		got, cmd := apply(m, key("r"))
		Expect(cmd).ToNot(BeNil())
		return deliver(got, cmd)
	}

	It("renders the feed once the first refresh returns", func() {
		out := loaded().View()
		Expect(out).To(ContainSubstring("CVE-2021-44228"))
		Expect(out).To(ContainSubstring("CRITICAL"))
		Expect(out).To(ContainSubstring("Live Feed"))
	})

	It("moves the cursor with j/k and clamps at both ends", func() {
		got := loaded()
		got, _ = apply(got, key("k")) // already at the top
		selected, ok := got.Selected()
		Expect(ok).To(BeTrue())
		Expect(selected.CVEID).To(Equal("CVE-2021-44228"))

		got, _ = apply(got, key("j"))
		selected, _ = got.Selected()
		Expect(selected.CVEID).To(Equal("CVE-2021-23337"))

		got, _ = apply(got, key("j")) // already at the bottom
		selected, _ = got.Selected()
		Expect(selected.CVEID).To(Equal("CVE-2021-23337"))
	})

	It("opens the finding's details on enter, with its blast radius loading alongside", func() {
		got := loaded()
		explorer.radius = model.BlastRadius{
			CVEID:              "CVE-2021-44228",
			VulnerablePackages: []string{"maven:log4j-core"},
			Repositories: []model.ImpactedRepository{
				{FullName: "acme/api", ViaPackage: "maven:log4j-core", Depth: 1, Direct: true},
			},
		}
		got, cmd := apply(got, tea.KeyMsg{Type: tea.KeyEnter})
		Expect(cmd).ToNot(BeNil())
		got = deliver(got, cmd)

		out := stripANSI(got.View())
		Expect(out).To(ContainSubstring("Details  CVE-2021-44228"))
		Expect(out).To(ContainSubstring("finding CVE-2021-44228"))
		Expect(explorer.gotCVE).To(Equal("CVE-2021-44228"), "the traversal started with the details")

		got, cmd = apply(got, key("3"))
		Expect(cmd).To(BeNil(), "already loaded: switching tabs fetches nothing")
		out = got.View()
		Expect(out).To(ContainSubstring("Graph Explorer"))
		Expect(out).To(ContainSubstring("acme/api"))
		Expect(out).To(ContainSubstring("1 repositories exposed"))
	})

	It("goes straight to the blast radius on b", func() {
		got := loaded()
		explorer.radius = model.BlastRadius{CVEID: "CVE-2021-44228", VulnerablePackages: []string{"maven:a"}}
		got, cmd := apply(got, key("b"))
		got = deliver(got, cmd)
		Expect(got.View()).To(ContainSubstring("Blast Radius  CVE-2021-44228"))
		Expect(got.View()).To(ContainSubstring("maven:a"))
	})

	It("does not carry one CVE's radius under another CVE's heading", func() {
		got := loaded()
		got, cmd := apply(got, tea.KeyMsg{Type: tea.KeyEnter})
		explorer.radius = model.BlastRadius{CVEID: "CVE-2021-44228", VulnerablePackages: []string{"maven:a"}}
		got = deliver(got, cmd)
		got, _ = apply(got, key("3"))
		Expect(got.View()).To(ContainSubstring("maven:a"))

		// Select the next finding and open it: the old result must be gone
		// while the new traversal is still in flight.
		got, _ = apply(got, key("1"))
		got, _ = apply(got, key("j"))
		got, _ = apply(got, tea.KeyMsg{Type: tea.KeyEnter})
		got, _ = apply(got, key("3"))

		Expect(got.View()).ToNot(ContainSubstring("maven:a"))
		Expect(got.View()).To(ContainSubstring("CVE-2021-23337"))
	})

	It("drops a traversal that answers for a finding no longer open", func() {
		got := loaded()
		explorer.radius = model.BlastRadius{CVEID: "CVE-2021-44228", VulnerablePackages: []string{"maven:stale"}}
		got, stale := apply(got, tea.KeyMsg{Type: tea.KeyEnter})
		got, _ = apply(got, key("1"))
		got, _ = apply(got, key("j"))
		got, _ = apply(got, tea.KeyMsg{Type: tea.KeyEnter})
		got = deliver(got, stale) // the first traversal lands late
		got, _ = apply(got, key("3"))

		Expect(got.View()).ToNot(ContainSubstring("maven:stale"))
	})

	It("ignores enter when the feed is empty", func() {
		search.feed = model.Feed{}
		got := loaded()
		_, cmd := apply(got, tea.KeyMsg{Type: tea.KeyEnter})
		Expect(cmd).To(BeNil())
	})

	It("edits the query with / and searches on enter", func() {
		got := loaded()
		got, _ = apply(got, key("/"))
		Expect(got.View()).To(ContainSubstring("search:"))

		got, _ = apply(got, tea.KeyMsg{Type: tea.KeyBackspace})
		got, _ = apply(got, tea.KeyMsg{Type: tea.KeyBackspace})
		got, _ = apply(got, tea.KeyMsg{Type: tea.KeyBackspace})
		got, _ = apply(got, key("log4j"))

		got, cmd := apply(got, tea.KeyMsg{Type: tea.KeyEnter})
		Expect(cmd).ToNot(BeNil())
		deliver(got, cmd)
		Expect(search.gotQuery).To(Equal("log4j"))
	})

	It("discards the edit on esc", func() {
		got := loaded()
		got, _ = apply(got, key("/"))
		got, _ = apply(got, key("xyz"))
		got, _ = apply(got, tea.KeyMsg{Type: tea.KeyEsc})

		Expect(got.View()).To(ContainSubstring(`query "cve"`))
		Expect(got.View()).ToNot(ContainSubstring("xyz"))
	})

	It("treats navigation keys as text while the query is being edited", func() {
		// Typing "j" into a search box must not move the cursor.
		got := loaded()
		got, _ = apply(got, key("/"))
		got, _ = apply(got, key("j"))

		selected, _ := got.Selected()
		Expect(selected.CVEID).To(Equal("CVE-2021-44228"))
		Expect(got.View()).To(ContainSubstring("cvej"))
	})

	It("switches tabs with tab, shift+tab and the number keys", func() {
		got := loaded()
		got, _ = apply(got, key("2"))
		Expect(got.View()).To(ContainSubstring("select a finding"))

		got, _ = apply(got, tea.KeyMsg{Type: tea.KeyTab})
		Expect(stripANSI(got.View())).To(ContainSubstring("▌ 3 Graph Explorer"))
		got, _ = apply(got, tea.KeyMsg{Type: tea.KeyTab})
		Expect(stripANSI(got.View())).To(ContainSubstring("▌ 4 Repositories"))
		got, _ = apply(got, tea.KeyMsg{Type: tea.KeyTab})
		Expect(got.View()).To(ContainSubstring("CVE-2021-44228"), "tab wraps round to the feed")

		got, _ = apply(got, tea.KeyMsg{Type: tea.KeyShiftTab})
		Expect(stripANSI(got.View())).To(ContainSubstring("▌ 4 Repositories"))
	})

	It("returns to the feed from details on esc", func() {
		got := loaded()
		got, _ = apply(got, tea.KeyMsg{Type: tea.KeyEnter})
		got, _ = apply(got, tea.KeyMsg{Type: tea.KeyEsc})
		Expect(stripANSI(got.View())).To(ContainSubstring("▌ 1 Live Feed"))
	})

	It("shows a backend failure instead of an empty list", func() {
		search.err = errors.New("connection refused")
		Expect(loaded().View()).To(ContainSubstring("connection refused"))
	})

	It("keeps the last good feed when a refresh fails", func() {
		got := loaded()
		search.err = errors.New("connection refused")
		got, _ = apply(got, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})

		selected, ok := got.Selected()
		Expect(ok).To(BeTrue())
		Expect(selected.CVEID).To(Equal("CVE-2021-44228"))
	})

	It("keeps the cursor in range when a refresh returns fewer results", func() {
		got := loaded()
		got, _ = apply(got, key("j"))

		search.feed = feedWith("CVE-2021-44228")
		got, cmd := apply(got, key("r"))
		got = deliver(got, cmd)

		selected, ok := got.Selected()
		Expect(ok).To(BeTrue())
		Expect(selected.CVEID).To(Equal("CVE-2021-44228"))
	})

	It("quits on q", func() {
		got, cmd := apply(loaded(), key("q"))
		Expect(cmd).ToNot(BeNil())
		Expect(got.View()).To(BeEmpty())
	})

	It("truncates a long headline to the terminal width", func() {
		search.feed = model.Feed{Hits: []model.SearchHit{{
			Vulnerability: model.Vulnerability{CVEID: "CVE-1", Title: strings.Repeat("x", 500)},
		}}}
		got := loaded()
		got, _ = apply(got, tea.WindowSizeMsg{Width: 100, Height: 40})

		for _, line := range strings.Split(got.View(), "\n") {
			Expect(len([]rune(line))).To(BeNumerically("<=", 120))
		}
	})
})

var _ = Describe("Feed row rendering", func() {
	var (
		search   *stubSearch
		explorer *stubExplorer
	)

	// render returns the feed rows of a loaded model, stripped of styling.
	render := func(feed model.Feed, width int) []string {
		GinkgoHelper()
		search = &stubSearch{feed: feed}
		explorer = &stubExplorer{}
		m := tui.New(search, explorer, tui.Options{Query: "cve", PageSize: 25})

		got, cmd := apply(m, key("r"))
		got = deliver(got, cmd)
		if width > 0 {
			got, _ = apply(got, tea.WindowSizeMsg{Width: width, Height: 40})
		}

		var rows []string
		for _, line := range strings.Split(stripANSI(got.View()), "\n") {
			if strings.Contains(line, "CVE-") || strings.Contains(line, "GHSA-") {
				rows = append(rows, line)
			}
		}
		return rows
	}

	It("flattens a tab inside an advisory title", func() {
		// Real data: NVD and vendor feeds wrap their titles, so tabs and
		// newlines arrive embedded. A tab counts as one rune but renders as
		// up to eight columns, which overflows the row and corrupts the frame.
		rows := render(model.Feed{Hits: []model.SearchHit{{
			Vulnerability: model.Vulnerability{
				CVEID: "CVE-2025-70290",
				Title: "[ADVISORY] Multiple Integer Overflows in U-Boot Filesystem\tParsing",
			},
		}}}, 200)

		Expect(rows).To(HaveLen(1))
		Expect(rows[0]).ToNot(ContainSubstring("\t"))
		Expect(rows[0]).To(ContainSubstring("Filesystem Parsing"))
	})

	It("flattens newlines and collapses the whitespace around them", func() {
		rows := render(model.Feed{Hits: []model.SearchHit{{
			Vulnerability: model.Vulnerability{
				CVEID: "CVE-2026-14297",
				Title: "A buffer overflow in the Bluetooth\n     Monitoring Service",
			},
		}}}, 200)

		Expect(rows[0]).ToNot(ContainSubstring("\n"))
		Expect(rows[0]).To(ContainSubstring("Bluetooth Monitoring Service"))
	})

	It("never emits a control character in a row", func() {
		rows := render(model.Feed{Hits: []model.SearchHit{{
			Vulnerability: model.Vulnerability{
				CVEID: "CVE-1", Title: "a\tb\nc\rd\ve",
			},
		}}}, 200)

		for _, r := range rows[0] {
			Expect(unicode.IsControl(r)).To(BeFalse(), "control character %q leaked into a row", r)
		}
	})

	It("keeps every row within the terminal width, selected or not", func() {
		// The selected and unselected paths used to be built separately and
		// drifted apart; a row that fitted in one wrapped in the other.
		hits := []model.SearchHit{}
		for _, id := range []string{"CVE-2025-70290", "CVE-2025-70291", "CVE-2025-70292"} {
			hits = append(hits, model.SearchHit{Vulnerability: model.Vulnerability{
				CVEID: id,
				Title: "[ADVISORY] Multiple Integer Overflows in U-Boot Filesystem\tParsing (CVE-2025-70290 through CVE-2025-70293)",
			}})
		}

		const width = 100
		for _, line := range render(model.Feed{Hits: hits}, width) {
			Expect(runewidth.StringWidth(line)).To(BeNumerically("<=", width),
				"row wider than the terminal will wrap and corrupt the frame: %q", line)
		}
	})

	It("keeps columns aligned when an id is longer than a CVE id", func() {
		// GHSA identifiers are 19 cells; a narrower id column would shunt
		// every column to their right.
		rows := render(model.Feed{Hits: []model.SearchHit{
			{Vulnerability: model.Vulnerability{CVEID: "CVE-2021-44228", Title: "short",
				Scores: []model.CVSS{{BaseScore: 10, Severity: "CRITICAL"}}}},
			{Vulnerability: model.Vulnerability{CVEID: "GHSA-jfh8-c2jp-5v3q", Title: "short",
				Scores: []model.CVSS{{BaseScore: 10, Severity: "CRITICAL"}}}},
		}}, 200)

		Expect(rows).To(HaveLen(2))
		Expect(column(rows[0], "CRITICAL")).To(Equal(column(rows[1], "CRITICAL")))
		Expect(column(rows[0], "short")).To(Equal(column(rows[1], "short")))
	})

	It("measures width in cells, not runes, for wide characters", func() {
		const width = 60
		rows := render(model.Feed{Hits: []model.SearchHit{{
			Vulnerability: model.Vulnerability{CVEID: "CVE-1", Title: strings.Repeat("東", 200)},
		}}}, width)

		Expect(runewidth.StringWidth(rows[0])).To(BeNumerically("<=", width))
	})
})

var _ = Describe("Layout", func() {
	newModel := func(feed model.Feed) tui.Model {
		return tui.New(&stubSearch{feed: feed}, &stubExplorer{},
			tui.Options{Query: "cve", PageSize: 25, Endpoint: "nexus http://localhost:8080/graphql"})
	}

	// boxEdges returns the widths of every box top/bottom border on screen.
	boxEdges := func(view string) []int {
		var widths []int
		for _, line := range strings.Split(stripANSI(view), "\n") {
			line = strings.TrimRight(line, " ")
			if strings.HasPrefix(line, "╭") || strings.HasPrefix(line, "╰") {
				widths = append(widths, runewidth.StringWidth(line))
			}
		}
		return widths
	}

	It("draws every box at the same width as the terminal", func() {
		// A prompt narrower than the panel above it reads as a rendering bug
		// even though nothing is broken.
		const width = 110
		m := newModel(feedWith("CVE-2021-44228"))
		got, cmd := apply(m, key("r"))
		got = deliver(got, cmd)
		got, _ = apply(got, tea.WindowSizeMsg{Width: width, Height: 40})

		edges := boxEdges(got.View())
		Expect(edges).ToNot(BeEmpty())
		for _, w := range edges {
			Expect(w).To(Equal(width))
		}
	})

	It("keeps the banner pinned at the top once results arrive", func() {
		m := newModel(feedWith("CVE-2021-44228"))
		sized, _ := apply(m, tea.WindowSizeMsg{Width: 110, Height: 40})
		Expect(stripANSI(sized.View())).To(ContainSubstring("██╗  ██╗"))

		got, cmd := apply(sized, key("r"))
		got = deliver(got, cmd)
		lines := strings.Split(stripANSI(got.View()), "\n")
		Expect(lines[0]).To(ContainSubstring("██╗  ██╗"), "the banner is the first line, for the whole session")
	})

	It("falls back to a wordmark in a terminal too narrow for the logo", func() {
		m := newModel(model.Feed{})
		got, _ := apply(m, tea.WindowSizeMsg{Width: 40, Height: 40})

		view := stripANSI(got.View())
		Expect(view).To(ContainSubstring("HYPERION"))
		Expect(view).ToNot(ContainSubstring("██╗  ██╗"), "a wrapped banner looks broken")
	})

	It("hides the banner in a short terminal, where rows matter more", func() {
		m := newModel(model.Feed{})
		got, _ := apply(m, tea.WindowSizeMsg{Width: 110, Height: 20})
		Expect(stripANSI(got.View())).ToNot(ContainSubstring("██╗  ██╗"))
	})

	It("animates a spinner while a request is in flight, and stops after", func() {
		m := newModel(feedWith("CVE-1"))
		Expect(stripANSI(m.View())).To(ContainSubstring("working…"))

		spun, cmd := apply(m, tui.SpinnerTick())
		Expect(cmd).ToNot(BeNil(), "the spinner re-arms while loading")
		Expect(stripANSI(spun.View())).To(ContainSubstring("working…"))

		got, refresh := apply(m, key("r"))
		got = deliver(got, refresh)
		Expect(stripANSI(got.View())).ToNot(ContainSubstring("working…"))

		_, idle := apply(got, tui.SpinnerTick())
		Expect(idle).To(BeNil(), "an idle deck must not keep waking the terminal")
	})
})

// manyHits builds a feed longer than any terminal is tall.
func manyHits(n int) model.Feed {
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		ids = append(ids, fmt.Sprintf("CVE-2026-%05d", i))
	}
	return feedWith(ids...)
}

// loadedAt returns a model that has fetched feed and knows its terminal size.
func loadedAt(feed model.Feed, width, height int) tui.Model {
	GinkgoHelper()
	m := tui.New(&stubSearch{feed: feed}, &stubExplorer{},
		tui.Options{Query: "cve", PageSize: 200, Endpoint: "nexus"})
	m, _ = apply(m, tea.WindowSizeMsg{Width: width, Height: height})
	got, cmd := apply(m, key("r"))
	return deliver(got, cmd)
}

func viewLines(m tui.Model) []string {
	return strings.Split(stripANSI(m.View()), "\n")
}

var _ = Describe("Fitting the terminal", func() {
	// Bubble Tea keeps only the last terminal-height lines of an oversized
	// frame, so overflow does not scroll — it deletes the top of the screen.
	// That is what made the banner vanish.

	It("never draws a frame taller than the terminal, whatever the size", func() {
		for _, size := range [][2]int{{110, 40}, {110, 24}, {80, 30}, {200, 60}, {70, 26}, {60, 20}, {40, 12}} {
			m := loadedAt(manyHits(80), size[0], size[1])
			details, _ := apply(m, tea.KeyMsg{Type: tea.KeyEnter})
			graph, _ := apply(details, key("3"))
			repos, _ := apply(m, key("4"))

			for _, view := range []tui.Model{m, details, graph, repos} {
				lines := viewLines(view)
				Expect(len(lines)).To(BeNumerically("<=", size[1]),
					"%dx%d: a frame taller than the screen loses its top lines", size[0], size[1])
				// A line wider than the terminal wraps in the terminal, which
				// is an extra line even though it holds no newline.
				for _, line := range lines {
					Expect(runewidth.StringWidth(line)).To(BeNumerically("<=", size[0]),
						"%dx%d: %q wraps", size[0], size[1], line)
				}
			}
		}
	})

	It("keeps the banner and tab bar on screen with a long list", func() {
		lines := viewLines(loadedAt(manyHits(80), 110, 40))

		Expect(lines[0]).To(ContainSubstring("██╗  ██╗"))
		Expect(strings.Join(lines[:10], "\n")).To(ContainSubstring("Live Feed"))
	})

	It("scrolls the list so the cursor is always visible", func() {
		m := loadedAt(manyHits(80), 110, 40)

		bottom, _ := apply(m, key("G"))
		selected, ok := bottom.Selected()
		Expect(ok).To(BeTrue())
		Expect(selected.CVEID).To(Equal("CVE-2026-00079"))
		Expect(stripANSI(bottom.View())).To(ContainSubstring("▸ CVE-2026-00079"))
		Expect(stripANSI(bottom.View())).ToNot(ContainSubstring("CVE-2026-00000 "),
			"the top of the list has scrolled away")

		top, _ := apply(bottom, key("g"))
		Expect(stripANSI(top.View())).To(ContainSubstring("▸ CVE-2026-00000"))
	})

	It("says which part of a long list is on screen", func() {
		view := stripANSI(loadedAt(manyHits(80), 110, 40).View())
		Expect(view).To(ContainSubstring("80 of 80  ·  1–"))
	})

	It("does not show a range when everything fits", func() {
		view := stripANSI(loadedAt(manyHits(3), 110, 40).View())
		Expect(view).ToNot(ContainSubstring("  ·  1–"))
	})

	It("pages with pgdown and pgup", func() {
		m := loadedAt(manyHits(80), 110, 40)
		down, _ := apply(m, tea.KeyMsg{Type: tea.KeyPgDown})
		selected, _ := down.Selected()
		Expect(selected.CVEID).ToNot(Equal("CVE-2026-00000"))

		up, _ := apply(down, tea.KeyMsg{Type: tea.KeyPgUp})
		selected, _ = up.Selected()
		Expect(selected.CVEID).To(Equal("CVE-2026-00000"))
	})

	It("keeps the cursor on screen after a resize to a smaller terminal", func() {
		m := loadedAt(manyHits(80), 110, 60)
		deep, _ := apply(m, key("G"))

		small, _ := apply(deep, tea.WindowSizeMsg{Width: 110, Height: 26})
		Expect(len(viewLines(small))).To(BeNumerically("<=", 26))
		Expect(stripANSI(small.View())).To(ContainSubstring("▸ CVE-2026-00079"))
	})

	It("gives way to the list, not the other way round, in a short terminal", func() {
		// The logo is decoration; the findings are the point.
		view := stripANSI(loadedAt(manyHits(80), 110, 22).View())
		Expect(view).ToNot(ContainSubstring("██╗  ██╗"))
		Expect(view).To(ContainSubstring("HYPERION"), "the tab bar still carries the name")
	})

	It("scrolls a blast radius taller than the screen", func() {
		repos := make([]model.ImpactedRepository, 0, 60)
		for i := 0; i < 60; i++ {
			repos = append(repos, model.ImpactedRepository{
				FullName: fmt.Sprintf("acme/service-%02d", i), ViaPackage: "npm:next", Depth: 1, Direct: true,
			})
		}
		explorer := &stubExplorer{radius: model.BlastRadius{
			CVEID: "CVE-2026-00000", VulnerablePackages: []string{"npm:next"}, Repositories: repos,
		}}
		m := tui.New(&stubSearch{feed: manyHits(5)}, explorer, tui.Options{Query: "cve", PageSize: 25})
		m, _ = apply(m, tea.WindowSizeMsg{Width: 110, Height: 40})
		m, cmd := apply(m, key("r"))
		m = deliver(m, cmd)
		m, cmd = apply(m, key("b"))
		m = deliver(m, cmd)

		Expect(len(viewLines(m))).To(BeNumerically("<=", 40))
		Expect(stripANSI(m.View())).To(ContainSubstring("lines 1–"))
		Expect(stripANSI(m.View())).ToNot(ContainSubstring("acme/service-59"))

		end, _ := apply(m, key("G"))
		Expect(stripANSI(end.View())).To(ContainSubstring("acme/service-59"))
		Expect(len(viewLines(end))).To(BeNumerically("<=", 40))
	})

	It("truncates a long query in the prompt instead of wrapping the box", func() {
		m := loadedAt(manyHits(3), 80, 30)
		m, _ = apply(m, key("/"))
		m, _ = apply(m, key(strings.Repeat("x", 300)))

		Expect(len(viewLines(m))).To(BeNumerically("<=", 30))
		for _, line := range viewLines(m) {
			Expect(runewidth.StringWidth(line)).To(BeNumerically("<=", 80))
		}
	})
})

// feedModel is a loaded model at a comfortable size, for paging specs.
func feedModel(search *stubSearch, query string, pageSize int) tui.Model {
	GinkgoHelper()
	m := tui.New(search, &stubExplorer{}, tui.Options{Query: query, PageSize: pageSize, Endpoint: "nexus"})
	m, _ = apply(m, tea.WindowSizeMsg{Width: 120, Height: 40})
	return deliver(m, m.Init())
}

var _ = Describe("Paging the feed", func() {
	It("opens on the live feed — newest first — when there is no query", func() {
		search := &stubSearch{feed: manyHits(80)}
		m := feedModel(search, "", 25)

		Expect(search.gotSort).To(Equal(model.SortNewest))
		Expect(search.gotQuery).To(BeEmpty())
		view := stripANSI(m.View())
		Expect(view).To(ContainSubstring("latest findings — 25 of 80"))
		Expect(view).To(ContainSubstring("none — showing the latest"))
	})

	It("loads the next page when the cursor reaches the end of what is loaded", func() {
		search := &stubSearch{feed: manyHits(80)}
		m := feedModel(search, "", 25)

		m, cmd := apply(m, key("G"))
		Expect(cmd).ToNot(BeNil(), "reaching the last row asks for more")
		Expect(stripANSI(m.View())).To(ContainSubstring("loading more"))

		m = deliver(m, cmd)
		Expect(search.moreCalls).To(Equal(1))
		Expect(stripANSI(m.View())).To(ContainSubstring("50 of 80"))

		selected, _ := m.Selected()
		Expect(selected.CVEID).To(Equal("CVE-2026-00024"), "the cursor stays where it was")
	})

	It("keeps going with the down key, one row past the last", func() {
		search := &stubSearch{feed: manyHits(30)}
		m := feedModel(search, "", 25)
		for i := 0; i < 23; i++ {
			m, _ = apply(m, key("j"))
		}
		m, cmd := apply(m, key("j")) // lands on row 25, the last loaded: that asks for more
		Expect(cmd).ToNot(BeNil())
		m = deliver(m, cmd)

		m, _ = apply(m, key("j"))
		selected, _ := m.Selected()
		Expect(selected.CVEID).To(Equal("CVE-2026-00025"), "row 26 is reachable now")
	})

	It("loads more on n, and stops offering more at the end", func() {
		search := &stubSearch{feed: manyHits(40)}
		m := feedModel(search, "", 25)
		Expect(stripANSI(m.View())).To(ContainSubstring("25 of 40"))

		m, cmd := apply(m, key("n"))
		m = deliver(m, cmd)
		m, _ = apply(m, key("G")) // the bottom of the list is on screen
		Expect(stripANSI(m.View())).To(ContainSubstring("40 of 40"))
		Expect(stripANSI(m.View())).ToNot(ContainSubstring("↓ more"))

		_, cmd = apply(m, key("n"))
		Expect(cmd).To(BeNil(), "nothing left to load")
	})

	It("does not fire a second page request while one is in flight", func() {
		search := &stubSearch{feed: manyHits(80)}
		m := feedModel(search, "", 25)
		m, first := apply(m, key("n"))
		Expect(first).ToNot(BeNil())
		_, second := apply(m, key("n"))
		Expect(second).To(BeNil())
	})

	It("keeps the loaded rows when the next page fails, and says so", func() {
		search := &stubSearch{feed: manyHits(80), moreErr: errors.New("gateway down")}
		m := feedModel(search, "", 25)
		m, cmd := apply(m, key("n"))
		m = deliver(m, cmd)

		view := stripANSI(m.View())
		Expect(view).To(ContainSubstring("25 of 80"))
		Expect(view).To(ContainSubstring("couldn't load more"))
		Expect(view).To(ContainSubstring("CVE-2026-00000"))
	})

	It("refreshes as many results as are loaded, not just the first page", func() {
		search := &stubSearch{feed: manyHits(80)}
		m := feedModel(search, "", 25)
		m, cmd := apply(m, key("n"))
		m = deliver(m, cmd)

		m, cmd = apply(m, key("r"))
		m = deliver(m, cmd)
		Expect(search.gotSize).To(Equal(50))
		Expect(stripANSI(m.View())).To(ContainSubstring("50 of 80"))
	})

	It("keeps the selection on the same finding when newer ones arrive on refresh", func() {
		search := &stubSearch{feed: manyHits(10)}
		m := feedModel(search, "", 25)
		m, _ = apply(m, key("j"))
		m, _ = apply(m, key("j"))
		selected, _ := m.Selected()
		Expect(selected.CVEID).To(Equal("CVE-2026-00002"))

		// Two newer findings land at the top.
		newer := model.Feed{Hits: append(feedWith("CVE-NEW-1", "CVE-NEW-2").Hits, manyHits(10).Hits...)}
		search.feed = newer
		m, cmd := apply(m, key("r"))
		m = deliver(m, cmd)

		selected, _ = m.Selected()
		Expect(selected.CVEID).To(Equal("CVE-2026-00002"), "the list moved; the selection did not")
	})

	It("drops a page that arrives after a refresh replaced the list", func() {
		search := &stubSearch{feed: manyHits(80)}
		m := feedModel(search, "", 25)
		m, stale := apply(m, key("n")) // request page 2...
		m, refresh := apply(m, key("r"))
		m = deliver(m, refresh) // ...but the refresh lands first
		m = deliver(m, stale)

		Expect(len(m.LoadedIDs())).To(Equal(25), "the stale page was not appended")
	})

	It("toggles between best match and newest for a search term", func() {
		search := &stubSearch{feed: manyHits(5)}
		m := feedModel(search, "next", 25)
		Expect(search.gotSort).To(Equal(model.SortRelevance))
		Expect(stripANSI(m.View())).To(ContainSubstring(`query "next" · best match`))

		m, cmd := apply(m, key("s"))
		m = deliver(m, cmd)
		Expect(search.gotSort).To(Equal(model.SortNewest))
		Expect(stripANSI(m.View())).To(ContainSubstring(`query "next" · newest`))
	})

	It("has nothing to toggle on the live feed", func() {
		m := feedModel(&stubSearch{feed: manyHits(5)}, "", 25)
		_, cmd := apply(m, key("s"))
		Expect(cmd).To(BeNil())
	})

	It("searches by best match when a term is submitted, and back to newest when cleared", func() {
		search := &stubSearch{feed: manyHits(5)}
		m := feedModel(search, "", 25)

		m, _ = apply(m, key("/"))
		m, _ = apply(m, key("lodash"))
		m, cmd := apply(m, tea.KeyMsg{Type: tea.KeyEnter})
		m = deliver(m, cmd)
		Expect(search.gotQuery).To(Equal("lodash"))
		Expect(search.gotSort).To(Equal(model.SortRelevance))

		m, _ = apply(m, key("/"))
		for i := 0; i < len("lodash"); i++ {
			m, _ = apply(m, tea.KeyMsg{Type: tea.KeyBackspace})
		}
		_, cmd = apply(m, tea.KeyMsg{Type: tea.KeyEnter})
		deliver(m, cmd)
		Expect(search.gotQuery).To(BeEmpty())
		Expect(search.gotSort).To(Equal(model.SortNewest))
	})

	It("polls with the submitted query, never a half-typed one", func() {
		search := &stubSearch{feed: manyHits(5)}
		m := feedModel(search, "lodash", 25)

		m, _ = apply(m, key("/"))
		m, _ = apply(m, key("xyz")) // the user is mid-edit
		_, cmd := apply(m, tui.PollTick())
		deliver(m, cmd)

		Expect(search.gotQuery).To(Equal("lodash"))
	})
})

var _ = Describe("Paging indicators", func() {
	It("shows ↓ more at the bottom of a list that has more", func() {
		search := &stubSearch{feed: manyHits(80)}
		m := feedModel(search, "", 10) // 10 rows fit entirely on screen
		Expect(stripANSI(m.View())).To(ContainSubstring("10 of 80  ·  ↓ more"))
	})

	It("does not skip findings when a page arrives for a list that changed", func() {
		// Two newer findings land, then a page fetched before they did
		// arrives. Its offsets are from the old list; appending it would
		// silently skip the two findings it shifted past.
		search := &stubSearch{feed: manyHits(80)}
		m := feedModel(search, "", 25)
		m, stale := apply(m, key("n"))

		search.feed = model.Feed{Hits: append(feedWith("CVE-NEW-1", "CVE-NEW-2").Hits, manyHits(80).Hits...)}
		m, refresh := apply(m, key("r"))
		m = deliver(m, refresh)
		m = deliver(m, stale)

		Expect(m.LoadedIDs()).To(HaveLen(25))
		Expect(m.LoadedIDs()[0]).To(Equal("CVE-NEW-1"))

		m, more := apply(m, key("n"))
		m = deliver(m, more)
		ids := m.LoadedIDs()
		Expect(ids).To(ContainElement("CVE-2026-00023"), "nothing skipped")
		Expect(ids).To(ContainElement("CVE-2026-00024"))
	})
})
