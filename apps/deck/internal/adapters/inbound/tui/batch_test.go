package tui_test

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mattn/go-runewidth"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/adapters/inbound/tui"
	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// kernelFeed builds what the Linux kernel CNA actually files: a run of
// consecutively numbered, unscored findings that all open with the same
// sentence.
func kernelFeed(n int) model.Feed {
	feed := model.Feed{}
	for i := range n {
		feed.Hits = append(feed.Hits, model.SearchHit{Vulnerability: model.Vulnerability{
			CVEID: fmt.Sprintf("CVE-2026-%05d", 93000+i),
			Description: fmt.Sprintf(
				"In the Linux kernel, the following vulnerability has been resolved: driver %d leaks a reference", i),
		}})
	}
	return feed
}

var _ = Describe("Folding a publisher's batch in the feed", func() {
	var m tui.Model

	BeforeEach(func() {
		m = loadedAt(kernelFeed(200), 140, 40)
	})

	It("shows one row for the whole run", func() {
		view := stripANSI(m.View())
		Expect(view).To(ContainSubstring("+ 200 findings"))
		Expect(view).To(ContainSubstring("In the Linux kernel, the following vulnerability has been resolved"))
		Expect(view).To(ContainSubstring("unknown 200"))
		// Exactly one of the findings is on screen as itself: none of them.
		Expect(strings.Count(view, "CVE-2026-93")).To(Equal(0))
	})

	It("says how many it folded, so none look lost", func() {
		Expect(stripANSI(m.View())).To(ContainSubstring("1 run folded"))
	})

	It("reports the worst rating inside rather than the first", func() {
		feed := kernelFeed(50)
		feed.Hits[30].Vulnerability.Scores = []model.CVSS{{BaseScore: 8.8, Severity: "HIGH"}}

		view := stripANSI(loadedAt(feed, 140, 40).View())
		Expect(view).To(ContainSubstring("HIGH"))
		Expect(view).To(ContainSubstring("high 1 · unknown 49"))
	})

	It("opens the run in place on enter, and closes it again", func() {
		opened, _ := apply(m, tea.KeyMsg{Type: tea.KeyEnter})
		view := stripANSI(opened.View())
		Expect(view).To(ContainSubstring("− 200 findings"))
		Expect(view).To(ContainSubstring("CVE-2026-93000"))

		closed, _ := apply(opened, tea.KeyMsg{Type: tea.KeyEnter})
		Expect(stripANSI(closed.View())).To(ContainSubstring("+ 200 findings"))
		Expect(stripANSI(closed.View())).ToNot(ContainSubstring("CVE-2026-93000"))
	})

	It("selects no finding while the cursor is on the fold", func() {
		// enter must not open a finding's details, and b must not traverse
		// one: the row stands for two hundred, and picking the first would
		// be picking arbitrarily.
		_, ok := m.Selected()
		Expect(ok).To(BeFalse())

		next, _ := apply(m, key("b"))
		Expect(stripANSI(next.View())).ToNot(ContainSubstring("Blast Radius"))
	})

	It("steps through the findings once the run is open", func() {
		opened, _ := apply(m, tea.KeyMsg{Type: tea.KeyEnter})
		moved, _ := apply(opened, key("j"))

		selected, ok := moved.Selected()
		Expect(ok).To(BeTrue())
		Expect(selected.CVEID).To(Equal("CVE-2026-93000"))
	})

	It("keeps a run open across a refresh", func() {
		// The fold is remembered by the wording it groups on, not by a
		// position in a list that a refresh replaces wholesale.
		opened, _ := apply(m, tea.KeyMsg{Type: tea.KeyEnter})
		refreshed := deliver(opened, func() tea.Msg { return tui.PollTick() })

		Expect(stripANSI(refreshed.View())).To(ContainSubstring("− 200 findings"))
	})

	It("leaves five in a row alone", func() {
		view := stripANSI(loadedAt(kernelFeed(5), 140, 40).View())
		Expect(view).ToNot(ContainSubstring("findings  "))
		Expect(view).To(ContainSubstring("CVE-2026-93000"))
		Expect(view).To(ContainSubstring("CVE-2026-93004"))
	})

	It("does not wrap a row at any width", func() {
		for _, width := range []int{60, 80, 100, 140} {
			sized, _ := apply(m, tea.WindowSizeMsg{Width: width, Height: 40})
			for _, line := range viewLines(sized) {
				Expect(runewidth.StringWidth(line)).To(BeNumerically("<=", width),
					fmt.Sprintf("width %d: %q", width, line))
			}
		}
	})
})
