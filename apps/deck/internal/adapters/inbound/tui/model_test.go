package tui_test

import (
	"context"
	"errors"
	"regexp"
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
type stubSearch struct {
	gotQuery string
	feed     model.Feed
	err      error
}

func (s *stubSearch) Handle(_ context.Context, query string, _ int) (model.Feed, error) {
	s.gotQuery = query
	s.feed.Query = query
	return s.feed, s.err
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

	It("opens the graph explorer for the selected finding on enter", func() {
		got := loaded()
		got, cmd := apply(got, tea.KeyMsg{Type: tea.KeyEnter})
		Expect(cmd).ToNot(BeNil())

		explorer.radius = model.BlastRadius{
			CVEID:              "CVE-2021-44228",
			VulnerablePackages: []string{"maven:log4j-core"},
			Repositories: []model.ImpactedRepository{
				{FullName: "acme/api", ViaPackage: "maven:log4j-core", Depth: 1, Direct: true},
			},
		}
		got = deliver(got, cmd)

		Expect(explorer.gotCVE).To(Equal("CVE-2021-44228"))
		out := got.View()
		Expect(out).To(ContainSubstring("Graph Explorer"))
		Expect(out).To(ContainSubstring("acme/api"))
		Expect(out).To(ContainSubstring("1 repositories exposed"))
	})

	It("does not carry one CVE's radius under another CVE's heading", func() {
		got := loaded()
		got, cmd := apply(got, tea.KeyMsg{Type: tea.KeyEnter})
		explorer.radius = model.BlastRadius{CVEID: "CVE-2021-44228", VulnerablePackages: []string{"maven:a"}}
		got = deliver(got, cmd)
		Expect(got.View()).To(ContainSubstring("maven:a"))

		// Select the next finding and open it: the old result must be gone
		// while the new traversal is still in flight.
		got, _ = apply(got, key("1"))
		got, _ = apply(got, key("j"))
		got, _ = apply(got, tea.KeyMsg{Type: tea.KeyEnter})

		Expect(got.View()).ToNot(ContainSubstring("maven:a"))
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

	It("switches tabs with tab and the number keys", func() {
		got := loaded()
		got, _ = apply(got, key("2"))
		Expect(got.View()).To(ContainSubstring("select a finding"))

		got, _ = apply(got, tea.KeyMsg{Type: tea.KeyTab})
		Expect(got.View()).To(ContainSubstring("CVE-2021-44228"))
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

	It("shows the banner before any data and drops it once results arrive", func() {
		m := newModel(feedWith("CVE-2021-44228"))
		sized, _ := apply(m, tea.WindowSizeMsg{Width: 110, Height: 40})
		Expect(stripANSI(sized.View())).To(ContainSubstring("██╗  ██╗"), "banner expected on the splash")

		got, cmd := apply(sized, key("r"))
		got = deliver(got, cmd)
		Expect(stripANSI(got.View())).ToNot(ContainSubstring("██╗  ██╗"),
			"the banner is an introduction, not furniture on every refresh")
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
