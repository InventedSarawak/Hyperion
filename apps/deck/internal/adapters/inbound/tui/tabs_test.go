package tui_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mattn/go-runewidth"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/adapters/inbound/tui"
	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// stubDetails serves the full record for the Details tab.
type stubDetails struct {
	record model.Vulnerability
	err    error
	gotID  string
}

func (s *stubDetails) Handle(_ context.Context, id string) (model.Vulnerability, error) {
	s.gotID = id
	return s.record, s.err
}

// stubRepos is an in-memory watchlist and GitHub owner listing.
type stubRepos struct {
	tracked     []model.TrackedRepository
	discovered  []model.DiscoveredRepository
	discoverErr error
	gotOwner    string
	gotTrack    []string
	gotUntrack  string
}

func (s *stubRepos) Tracked(context.Context) ([]model.TrackedRepository, error) {
	return s.tracked, nil
}

func (s *stubRepos) Discover(_ context.Context, owner string) ([]model.DiscoveredRepository, error) {
	s.gotOwner = owner
	return s.discovered, s.discoverErr
}

func (s *stubRepos) Track(_ context.Context, names []string) ([]model.TrackedRepository, error) {
	s.gotTrack = names
	out := make([]model.TrackedRepository, 0, len(names))
	for _, n := range names {
		out = append(out, model.TrackedRepository{FullName: n, Status: model.ScanPending})
	}
	return out, nil
}

func (s *stubRepos) Untrack(_ context.Context, name string) error {
	s.gotUntrack = name
	return nil
}

// nvdLike is a record the way NVD sends it: no title, only a description.
var nvdLike = model.Vulnerability{
	CVEID: "CVE-2026-67315",
	Description: "Axios is a promise based HTTP client. Prior to 1.13.5, the NO_PROXY check " +
		"did not treat 0.0.0.0 as a local address, so requests to it were routed through the proxy.",
	Scores:      []model.CVSS{{Version: "3.1", BaseScore: 5.3, Severity: "MEDIUM", Vector: "CVSS:3.1/AV:N/AC:L"}},
	PublishedAt: time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC),
	Sources:     []string{"nvd"},
}

var _ = Describe("Feed rows for records with no title", func() {
	It("shows the description as the headline instead of the id a second time", func() {
		m := loadedAt(model.Feed{Hits: []model.SearchHit{{Vulnerability: nvdLike}}}, 140, 40)

		var row string
		for _, line := range viewLines(m) {
			if strings.Contains(line, "CVE-2026-67315") {
				row = line
			}
		}
		Expect(row).To(ContainSubstring("Axios is a promise based HTTP client"))
		Expect(strings.Count(row, "CVE-2026-67315")).To(Equal(1))
	})
})

var _ = Describe("Details tab", func() {
	var (
		details *stubDetails
		m       tui.Model
	)

	open := func(width, height int, hit model.Vulnerability) tui.Model {
		GinkgoHelper()
		m = tui.New(&stubSearch{feed: model.Feed{Hits: []model.SearchHit{{Vulnerability: hit}}}}, &stubExplorer{},
			tui.Options{Query: "axios", PageSize: 25, Details: details})
		m, _ = apply(m, tea.WindowSizeMsg{Width: width, Height: height})
		m, cmd := apply(m, key("r"))
		m = deliver(m, cmd)
		m, cmd = apply(m, tea.KeyMsg{Type: tea.KeyEnter})
		return deliver(m, cmd)
	}

	BeforeEach(func() {
		full := nvdLike
		full.Sources = []string{"nvd", "github_advisory"}
		full.AffectedPackages = []model.AffectedPackage{{Package: "npm:axios", VersionRange: "< 1.13.5"}}
		full.References = []string{"https://github.com/axios/axios/security/advisories/GHSA-f4gw-2p7v-4548"}
		details = &stubDetails{record: full}
	})

	It("shows everything known about the finding, from the full record", func() {
		view := stripANSI(open(140, 60, nvdLike).View())

		Expect(details.gotID).To(Equal("CVE-2026-67315"))
		Expect(view).To(ContainSubstring("MEDIUM 5.3"))
		Expect(view).To(ContainSubstring("Published   2026-07-20"))
		Expect(view).To(ContainSubstring("Reported by nvd, github_advisory"))
		Expect(view).To(ContainSubstring("CVSS 3.1"))
		Expect(view).To(ContainSubstring("CVSS:3.1/AV:N/AC:L"))
		Expect(view).To(ContainSubstring("npm:axios  < 1.13.5"))
		Expect(view).To(ContainSubstring("Axios is a promise based HTTP client"))
		Expect(view).To(ContainSubstring("GHSA-f4gw-2p7v-4548"))
	})

	It("keeps what the search result carried when the full record cannot be loaded", func() {
		details.err = errors.New("gateway down")
		view := stripANSI(open(140, 60, nvdLike).View())

		Expect(view).To(ContainSubstring("couldn't load the full record: gateway down"))
		Expect(view).To(ContainSubstring("Axios is a promise based HTTP client"))
	})

	It("says plainly when no feed has linked the finding to a library", func() {
		details.record = nvdLike
		Expect(stripANSI(open(140, 60, nvdLike).View())).To(ContainSubstring("blast radius cannot be computed"))
	})

	It("re-flows a long description to the terminal and scrolls it", func() {
		long := nvdLike
		long.Description = strings.Repeat("A long hard-wrapped advisory\nparagraph that keeps going. ", 60) +
			"\n\n### Impact\n\n- first consequence\n- second consequence\n\nFINAL-SENTENCE."
		details.record = long

		const width, height = 90, 30
		m := open(width, height, long)
		lines := viewLines(m)
		Expect(len(lines)).To(BeNumerically("<=", height))
		for _, line := range lines {
			Expect(runewidth.StringWidth(line)).To(BeNumerically("<=", width), "%q wraps", line)
		}
		Expect(stripANSI(m.View())).To(ContainSubstring("lines 1–"))
		Expect(stripANSI(m.View())).ToNot(ContainSubstring("FINAL-SENTENCE."))

		end, _ := apply(m, key("G"))
		view := stripANSI(end.View())
		Expect(view).To(ContainSubstring("FINAL-SENTENCE."))
		Expect(view).To(MatchRegexp(`• first consequence\s*│\n│\s+• second consequence`), "list items keep their own lines")
		Expect(len(viewLines(end))).To(BeNumerically("<=", height))
	})

	It("renders a Markdown description instead of showing its markup", func() {
		md := nvdLike
		md.Description = "### Impact\n\nThe **NO_PROXY** check is `bypassed`.\n\n- first\n- second\n\n" +
			"See [the advisory](https://example.test/advisory)."
		details.record = md

		view := stripANSI(open(120, 60, md).View())
		Expect(view).To(ContainSubstring("Impact"))
		Expect(view).To(ContainSubstring("NO_PROXY"))
		Expect(view).To(ContainSubstring("• first"))
		Expect(view).To(ContainSubstring("• second"))
		Expect(view).ToNot(ContainSubstring("**"))
		Expect(view).ToNot(ContainSubstring("`"))
	})

	It("keeps a URL longer than the panel inside it", func() {
		long := nvdLike
		long.Description = "Details at https://example.test/" + strings.Repeat("x", 200) + "/END-OF-URL and after."
		details.record = long

		const width, height = 80, 60
		m := open(width, height, long)
		for _, line := range viewLines(m) {
			Expect(runewidth.StringWidth(line)).To(BeNumerically("<=", width), "%q wraps", line)
		}
		// Word wrap may break the URL at a hyphen; none of it is lost.
		Expect(stripANSI(m.View())).To(ContainSubstring("OF-URL and after."))
	})

	It("opens the blast radius from details on enter", func() {
		m := open(140, 40, nvdLike)
		m, _ = apply(m, tea.KeyMsg{Type: tea.KeyEnter})
		Expect(stripANSI(m.View())).To(ContainSubstring("▌ 3 Graph Explorer"))
	})
})

var _ = Describe("Repositories tab", func() {
	var repos *stubRepos

	// reposModel is a loaded model sitting on the Repositories tab.
	reposModel := func(width, height int) tui.Model {
		GinkgoHelper()
		m := tui.New(&stubSearch{feed: feedWith("CVE-1")}, &stubExplorer{},
			tui.Options{Query: "cve", PageSize: 25, Repositories: repos})
		m, _ = apply(m, tea.WindowSizeMsg{Width: width, Height: height})
		m, cmd := apply(m, key("4"))
		Expect(cmd).ToNot(BeNil(), "opening the tab loads the watchlist")
		return deliver(m, cmd)
	}

	typeText := func(m tui.Model, text string) tui.Model {
		GinkgoHelper()
		for _, r := range text {
			m, _ = apply(m, key(string(r)))
		}
		return m
	}

	BeforeEach(func() {
		repos = &stubRepos{
			tracked: []model.TrackedRepository{
				{FullName: "eslint/eslint", Status: model.ScanScanned, DependencyCount: 88, LastScanAt: time.Now().Add(-2 * time.Hour)},
				{FullName: "vercel/next.js", Status: model.ScanFailed, LastError: "rate limited", LastScanAt: time.Now()},
			},
			discovered: []model.DiscoveredRepository{
				{FullName: "vercel/next.js", Stars: 130000, Language: "JavaScript", Tracked: true},
				{FullName: "vercel/swr", Stars: 30000, Language: "TypeScript", Description: "React Hooks for Data Fetching"},
				{FullName: "vercel/ai", Stars: 12000, Language: "TypeScript"},
				{FullName: "vercel/old", Archived: true},
			},
		}
	})

	It("lists what is tracked, with each repository's scan state", func() {
		view := stripANSI(reposModel(140, 40).View())

		Expect(view).To(ContainSubstring("Repositories  2 tracked  ·  1 failed"))
		Expect(view).To(ContainSubstring("eslint/eslint"))
		Expect(view).To(ContainSubstring("88"))
		Expect(view).To(ContainSubstring("2h ago"))
		Expect(view).To(ContainSubstring("rate limited"))
	})

	It("adds repositories: owner, then pick with space, then enter", func() {
		m := reposModel(140, 40)
		m, _ = apply(m, key("a"))
		Expect(stripANSI(m.View())).To(ContainSubstring("add from github user or org:"))

		m = typeText(m, "vercel") // "a", "d", "s" are shortcuts elsewhere; here they are text
		m, cmd := apply(m, tea.KeyMsg{Type: tea.KeyEnter})
		m = deliver(m, cmd)
		Expect(repos.gotOwner).To(Equal("vercel"))

		view := stripANSI(m.View())
		Expect(view).To(ContainSubstring("Add from vercel  4 repositories  ·  0 selected"))
		Expect(view).To(ContainSubstring("[✓] vercel/next.js"), "already tracked, shown checked")
		Expect(view).To(ContainSubstring("React Hooks for Data Fetching"))
		Expect(view).To(ContainSubstring("vercel/old (archived)"))

		// Space on a tracked repository does nothing but move on; on the next
		// two it selects and moves on.
		m, _ = apply(m, tea.KeyMsg{Type: tea.KeySpace, Runes: []rune(" ")})
		m, _ = apply(m, tea.KeyMsg{Type: tea.KeySpace, Runes: []rune(" ")})
		m, _ = apply(m, tea.KeyMsg{Type: tea.KeySpace, Runes: []rune(" ")})
		view = stripANSI(m.View())
		Expect(view).To(ContainSubstring("2 selected"))
		Expect(view).To(ContainSubstring("[x] vercel/swr"))

		m, cmd = apply(m, tea.KeyMsg{Type: tea.KeyEnter})
		m = deliver(m, cmd)
		Expect(repos.gotTrack).To(Equal([]string{"vercel/swr", "vercel/ai"}))

		view = stripANSI(m.View())
		Expect(view).To(ContainSubstring("tracking 2 repositories"))
		Expect(view).To(ContainSubstring("vercel/swr"))
		Expect(view).To(ContainSubstring("pending"))
	})

	It("selects every untracked repository with a, and clears them with a again", func() {
		m := reposModel(140, 40)
		m, _ = apply(m, key("a"))
		m = typeText(m, "vercel")
		m, cmd := apply(m, tea.KeyMsg{Type: tea.KeyEnter})
		m = deliver(m, cmd)

		m, _ = apply(m, key("a"))
		Expect(stripANSI(m.View())).To(ContainSubstring("3 selected"))
		m, _ = apply(m, key("a"))
		Expect(stripANSI(m.View())).To(ContainSubstring("0 selected"))
	})

	It("says why an owner could not be listed", func() {
		repos.discoverErr = errors.New("repository catalog: owner not found: nobody")
		m := reposModel(140, 40)
		m, _ = apply(m, key("a"))
		m = typeText(m, "nobody")
		m, cmd := apply(m, tea.KeyMsg{Type: tea.KeyEnter})
		m = deliver(m, cmd)

		Expect(stripANSI(m.View())).To(ContainSubstring("couldn't list nobody: repository catalog: owner not found"))
	})

	It("removes a repository only after confirmation", func() {
		m := reposModel(140, 40)
		m, _ = apply(m, key("d"))
		Expect(stripANSI(m.View())).To(ContainSubstring("remove eslint/eslint and its edges from the graph? y / n"))

		m, _ = apply(m, key("n"))
		Expect(repos.gotUntrack).To(BeEmpty())

		m, _ = apply(m, key("d"))
		m, cmd := apply(m, key("y"))
		m = deliver(m, cmd)
		Expect(repos.gotUntrack).To(Equal("eslint/eslint"))
		view := stripANSI(m.View())
		Expect(view).To(ContainSubstring("removed eslint/eslint"))
		Expect(view).To(ContainSubstring("1 tracked"))
	})

	It("re-queues the selected repository for a scan on s", func() {
		m := reposModel(140, 40)
		m, _ = apply(m, key("j"))
		_, cmd := apply(m, key("s"))
		deliver(m, cmd)
		Expect(repos.gotTrack).To(Equal([]string{"vercel/next.js"}))
	})

	It("fits the terminal with a long picker list, and scrolls it", func() {
		for i := 0; i < 120; i++ {
			repos.discovered = append(repos.discovered, model.DiscoveredRepository{
				FullName:    fmt.Sprintf("big/repo-%03d", i),
				Description: strings.Repeat("a very long description ", 10),
			})
		}
		const width, height = 100, 30
		m := reposModel(width, height)
		m, _ = apply(m, key("a"))
		m = typeText(m, "big")
		m, cmd := apply(m, tea.KeyMsg{Type: tea.KeyEnter})
		m = deliver(m, cmd)
		m, _ = apply(m, key("G"))

		lines := viewLines(m)
		Expect(len(lines)).To(BeNumerically("<=", height))
		for _, line := range lines {
			Expect(runewidth.StringWidth(line)).To(BeNumerically("<=", width), "%q wraps", line)
		}
		Expect(stripANSI(m.View())).To(ContainSubstring("▸ [ ] big/repo-119"))
	})

	It("explains the watchlist when nothing is tracked yet", func() {
		repos.tracked = nil
		Expect(stripANSI(reposModel(140, 40).View())).To(ContainSubstring("press a to add repositories"))
	})
})
