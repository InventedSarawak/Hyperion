package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// repoMode is what the Repositories tab is doing.
type repoMode int

const (
	// repoList shows the watchlist.
	repoList repoMode = iota
	// repoOwnerPrompt is typing the GitHub user or organization to add from.
	repoOwnerPrompt
	// repoPicker is choosing among that owner's repositories.
	repoPicker
	// repoConfirmRemove is waiting for y/n before untracking.
	repoConfirmRemove
	// repoFindings lists the vulnerabilities the selected repository has.
	repoFindings
)

// repoState is the Repositories tab: the watchlist, and the add flow
// (owner prompt → picker → track) layered over it.
type repoState struct {
	mode repoMode

	list    []model.TrackedRepository
	loaded  bool
	loading bool
	err     error
	cursor  int
	offset  int

	owner       string // the owner being typed
	discovered  []model.DiscoveredRepository
	pickOwner   string // the owner the picker is showing
	discovering bool
	pickCursor  int
	pickOffset  int
	picked      map[string]bool
	tracking    bool

	// notice is a one-line outcome shown above the list: what was just
	// added or removed, or why it could not be.
	notice   string
	noticeOK bool

	// The findings view: one repository's vulnerabilities.
	exposure        model.RepositoryExposure
	exposureFor     string
	exposureLoading bool
	exposureErr     error
	findCursor      int
	findOffset      int
	showUnaffected  bool
}

// selectedFinding is the finding under the cursor in the findings view.
func (r repoState) selectedFinding() (model.RepositoryFinding, bool) {
	if r.findCursor < 0 || r.findCursor >= len(r.exposure.Findings) {
		return model.RepositoryFinding{}, false
	}
	return r.exposure.Findings[r.findCursor], true
}

func (r repoState) busy() bool { return r.loading || r.discovering || r.tracking }

// pending reports whether any tracked repository is waiting for its scan.
func (r repoState) pending() bool {
	for _, t := range r.list {
		if t.Status == model.ScanPending {
			return true
		}
	}
	return false
}

// selected is the tracked repository under the cursor.
func (r repoState) selected() (model.TrackedRepository, bool) {
	if r.cursor < 0 || r.cursor >= len(r.list) {
		return model.TrackedRepository{}, false
	}
	return r.list[r.cursor], true
}

// pickedNames is the picker's selection, in list order.
func (r repoState) pickedNames() []string {
	var out []string
	for _, d := range r.discovered {
		if r.picked[d.FullName] {
			out = append(out, d.FullName)
		}
	}
	return out
}

// --- messages ---

type reposMsg struct {
	list []model.TrackedRepository
	err  error
}

type discoverMsg struct {
	owner string
	found []model.DiscoveredRepository
	err   error
}

type trackMsg struct {
	added []model.TrackedRepository
	err   error
}

type untrackMsg struct {
	fullName string
	err      error
}

type exposureMsg struct {
	fullName string
	exposure model.RepositoryExposure
	err      error
}

// reposPollMsg re-reads the watchlist while scans are pending, so a
// repository visibly moves from "pending" to "scanned" without a keypress.
type reposPollMsg time.Time

// reposPollInterval is how often the watchlist is re-read while a scan is
// pending. The scanner checks for new work every 30s; polling faster than that
// would only repeat the same answer.
const reposPollInterval = 5 * time.Second

// --- commands ---

func (m Model) loadRepos() tea.Cmd {
	manager := m.opts.Repositories
	return func() tea.Msg {
		list, err := manager.Tracked(context.Background())
		return reposMsg{list: list, err: err}
	}
}

func (m Model) discover(owner string) tea.Cmd {
	manager := m.opts.Repositories
	return func() tea.Msg {
		found, err := manager.Discover(context.Background(), owner)
		return discoverMsg{owner: owner, found: found, err: err}
	}
}

func (m Model) track(names []string) tea.Cmd {
	manager := m.opts.Repositories
	return func() tea.Msg {
		added, err := manager.Track(context.Background(), names)
		return trackMsg{added: added, err: err}
	}
}

func (m Model) untrack(fullName string) tea.Cmd {
	manager := m.opts.Repositories
	return func() tea.Msg {
		return untrackMsg{fullName: fullName, err: manager.Untrack(context.Background(), fullName)}
	}
}

func (m Model) loadExposure(fullName string, includeUnaffected bool) tea.Cmd {
	loader := m.opts.Findings
	return func() tea.Msg {
		exp, err := loader.Handle(context.Background(), fullName, includeUnaffected)
		return exposureMsg{fullName: fullName, exposure: exp, err: err}
	}
}

// openFindings shows the vulnerabilities of the selected repository.
func (m Model) openFindings() (Model, tea.Cmd) {
	repo, ok := m.repos.selected()
	if !ok || m.opts.Findings == nil {
		return m, nil
	}
	m.repos.mode = repoFindings
	if !strings.EqualFold(repo.FullName, m.repos.exposureFor) {
		m.repos.exposure = model.RepositoryExposure{}
		m.repos.findCursor, m.repos.findOffset = 0, 0
	}
	m.repos.exposureFor = repo.FullName
	m.repos.exposureErr = nil
	m.repos.exposureLoading = true
	return m, tea.Batch(m.loadExposure(repo.FullName, m.repos.showUnaffected), m.spin())
}

func pollRepos() tea.Cmd {
	return tea.Tick(reposPollInterval, func(t time.Time) tea.Msg { return reposPollMsg(t) })
}

// enterRepos loads the watchlist the first time the tab is opened.
func (m Model) enterRepos() (Model, tea.Cmd) {
	if m.opts.Repositories == nil || m.repos.loaded || m.repos.loading {
		return m, nil
	}
	m.repos.loading = true
	return m, tea.Batch(m.loadRepos(), m.spin())
}

// --- message handling ---

func (m Model) updateRepoMsg(msg tea.Msg) (Model, tea.Cmd) {
	switch msg := msg.(type) {
	case reposMsg:
		m.repos.loading = false
		m.repos.err = msg.err
		if msg.err == nil {
			keep, _ := m.repos.selected()
			m.repos.list = msg.list
			m.repos.loaded = true
			// Keep the cursor on the same repository across a reload.
			for i, t := range m.repos.list {
				if strings.EqualFold(t.FullName, keep.FullName) {
					m.repos.cursor = i
				}
			}
		}
		if m.repos.pending() {
			return m, pollRepos()
		}
		return m, nil

	case exposureMsg:
		if !strings.EqualFold(msg.fullName, m.repos.exposureFor) {
			return m, nil // a different repository has been opened since
		}
		m.repos.exposureLoading = false
		m.repos.exposureErr = msg.err
		if msg.err == nil {
			m.repos.exposure = msg.exposure
		}
		return m, nil

	case reposPollMsg:
		// Only while someone is looking and something is still pending.
		if m.tab != TabRepos || m.repos.loading || !m.repos.pending() {
			return m, nil
		}
		m.repos.loading = true
		return m, tea.Batch(m.loadRepos(), m.spin())

	case discoverMsg:
		if msg.owner != m.repos.pickOwner {
			return m, nil // the user has moved on to another owner
		}
		m.repos.discovering = false
		if msg.err != nil {
			m.repos.mode = repoList
			m.repos.notice, m.repos.noticeOK = "couldn't list "+msg.owner+": "+msg.err.Error(), false
			return m, nil
		}
		m.repos.discovered = msg.found
		if len(msg.found) == 0 {
			m.repos.mode = repoList
			m.repos.notice, m.repos.noticeOK = msg.owner+" has no public repositories", false
		}
		return m, nil

	case trackMsg:
		m.repos.tracking = false
		if msg.err != nil {
			m.repos.notice, m.repos.noticeOK = "couldn't add: "+msg.err.Error(), false
			return m, nil
		}
		m.repos.mode = repoList
		m.repos.notice, m.repos.noticeOK = fmt.Sprintf("tracking %d %s — scans start within 30s",
			len(msg.added), plural(len(msg.added), "repository", "repositories")), true
		m.repos.list = mergeTracked(m.repos.list, msg.added)
		return m, pollRepos()

	case untrackMsg:
		m.repos.tracking = false
		m.repos.mode = repoList
		if msg.err != nil {
			m.repos.notice, m.repos.noticeOK = "couldn't remove "+msg.fullName+": "+msg.err.Error(), false
			return m, nil
		}
		m.repos.notice, m.repos.noticeOK = "removed "+msg.fullName+" and its dependency edges from the graph", true
		kept := m.repos.list[:0:0]
		for _, t := range m.repos.list {
			if !strings.EqualFold(t.FullName, msg.fullName) {
				kept = append(kept, t)
			}
		}
		m.repos.list = kept
		return m, nil
	}
	return m, nil
}

// mergeTracked folds newly tracked entries into the list, replacing any with
// the same name, and keeps it sorted the way cortex sorts it.
func mergeTracked(list, added []model.TrackedRepository) []model.TrackedRepository {
	byName := make(map[string]model.TrackedRepository, len(list)+len(added))
	for _, t := range list {
		byName[strings.ToLower(t.FullName)] = t
	}
	for _, t := range added {
		byName[strings.ToLower(t.FullName)] = t
	}
	out := make([]model.TrackedRepository, 0, len(byName))
	for _, t := range byName {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].FullName) < strings.ToLower(out[j].FullName) })
	return out
}

// --- keys ---

// typingOwner reports whether keystrokes belong to the owner prompt.
func (m Model) typingOwner() bool { return m.tab == TabRepos && m.repos.mode == repoOwnerPrompt }

// updateOwnerPrompt handles keys while the owner is being typed.
func (m Model) updateOwnerPrompt(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter:
		owner := strings.TrimSpace(m.repos.owner)
		if owner == "" {
			return m, nil
		}
		m.repos.mode = repoPicker
		m.repos.pickOwner = owner
		m.repos.discovered = nil
		m.repos.picked = map[string]bool{}
		m.repos.pickCursor, m.repos.pickOffset = 0, 0
		m.repos.discovering = true
		m.repos.notice = ""
		return m, tea.Batch(m.discover(owner), m.spin())
	case tea.KeyEsc:
		m.repos.mode = repoList
		return m, nil
	case tea.KeyBackspace:
		if runes := []rune(m.repos.owner); len(runes) > 0 {
			m.repos.owner = string(runes[:len(runes)-1])
		}
		return m, nil
	case tea.KeyCtrlC:
		m.quitting = true
		return m, tea.Quit
	case tea.KeyRunes:
		m.repos.owner += string(msg.Runes)
		return m, nil
	}
	return m, nil
}

// updateRepoKeys handles the Repositories tab's own keys. It reports false
// for keys it does not use, so the global ones (tab, q, 1–4) still work.
func (m Model) updateRepoKeys(msg tea.KeyMsg) (Model, tea.Cmd, bool) {
	if m.opts.Repositories == nil {
		return m, nil, false
	}
	switch m.repos.mode {
	case repoConfirmRemove:
		switch msg.String() {
		case "y", "Y":
			if repo, ok := m.repos.selected(); ok {
				m.repos.tracking = true
				return m, tea.Batch(m.untrack(repo.FullName), m.spin()), true
			}
			m.repos.mode = repoList
		default:
			m.repos.mode = repoList
			m.repos.notice = ""
		}
		return m, nil, true

	case repoPicker:
		return m.updatePicker(msg)
	case repoFindings:
		return m.updateFindingKeys(msg)
	}

	switch msg.String() {
	case "enter":
		next, cmd := m.openFindings()
		return next, cmd, true
	case "a", "+":
		m.repos.mode = repoOwnerPrompt
		m.repos.owner = ""
		return m, nil, true
	case "d", "x", "delete":
		if _, ok := m.repos.selected(); ok {
			m.repos.mode = repoConfirmRemove
		}
		return m, nil, true
	case "s":
		// Re-tracking re-queues the repository for an immediate scan.
		if repo, ok := m.repos.selected(); ok && !m.repos.tracking {
			m.repos.tracking = true
			return m, tea.Batch(m.track([]string{repo.FullName}), m.spin()), true
		}
		return m, nil, true
	case "r":
		if !m.repos.loading {
			m.repos.loading = true
			return m, tea.Batch(m.loadRepos(), m.spin()), true
		}
		return m, nil, true
	case "j", "down":
		m.repos.cursor++
		return m, nil, true
	case "k", "up":
		m.repos.cursor--
		return m, nil, true
	case "g", "home":
		m.repos.cursor = 0
		return m, nil, true
	case "G", "end":
		m.repos.cursor = len(m.repos.list) - 1
		return m, nil, true
	case "pgdown", "ctrl+d":
		m.repos.cursor += max(1, m.repoRows()-1)
		return m, nil, true
	case "pgup", "ctrl+u":
		m.repos.cursor -= max(1, m.repoRows()-1)
		return m, nil, true
	}
	return m, nil, false
}

// updatePicker handles keys while choosing an owner's repositories.
func (m Model) updatePicker(msg tea.KeyMsg) (Model, tea.Cmd, bool) {
	switch msg.String() {
	case "esc":
		m.repos.mode = repoList
		m.repos.pickOwner = ""
		return m, nil, true
	case " ", "space":
		if m.repos.pickCursor < len(m.repos.discovered) {
			d := m.repos.discovered[m.repos.pickCursor]
			if !d.Tracked {
				m.repos.picked[d.FullName] = !m.repos.picked[d.FullName]
			}
		}
		// Space also moves on, so a run of repositories is ticked with a
		// run of keypresses.
		m.repos.pickCursor++
		return m, nil, true
	case "a":
		// Select every untracked repository, or clear them all if they
		// already are.
		all := true
		for _, d := range m.repos.discovered {
			if !d.Tracked && !m.repos.picked[d.FullName] {
				all = false
			}
		}
		for _, d := range m.repos.discovered {
			if !d.Tracked {
				m.repos.picked[d.FullName] = !all
			}
		}
		return m, nil, true
	case "enter":
		names := m.repos.pickedNames()
		if len(names) == 0 || m.repos.tracking {
			return m, nil, true
		}
		m.repos.tracking = true
		return m, tea.Batch(m.track(names), m.spin()), true
	case "j", "down":
		m.repos.pickCursor++
		return m, nil, true
	case "k", "up":
		m.repos.pickCursor--
		return m, nil, true
	case "g", "home":
		m.repos.pickCursor = 0
		return m, nil, true
	case "G", "end":
		m.repos.pickCursor = len(m.repos.discovered) - 1
		return m, nil, true
	case "pgdown", "ctrl+d":
		m.repos.pickCursor += max(1, m.repoRows()-1)
		return m, nil, true
	case "pgup", "ctrl+u":
		m.repos.pickCursor -= max(1, m.repoRows()-1)
		return m, nil, true
	}
	return m, nil, false
}

// --- view ---

// Column widths for the watchlist and the picker, in cells.
const (
	colRepoStatus = 9
	colRepoDeps   = 6
	colRepoWhen   = 10
	colRepoRisk   = 16
	colPickMark   = 4
	colPickStars  = 7
	colPickLang   = 11
)

func (m Model) reposView() string {
	if m.opts.Repositories == nil {
		return panel("Repositories", styleDim.Render("not connected to a service that manages the watchlist"), m.width)
	}
	if m.repos.mode == repoPicker {
		return m.pickerView()
	}
	if m.repos.mode == repoFindings {
		return m.findingsView()
	}

	title := fmt.Sprintf("Repositories  %d tracked", len(m.repos.list))
	if n := m.countStatus(model.ScanPending); n > 0 {
		title += fmt.Sprintf("  ·  %d pending", n)
	}
	if n := m.countStatus(model.ScanFailed); n > 0 {
		title += fmt.Sprintf("  ·  %d failed", n)
	}

	var lines []string
	if notice := m.repoNotice(); notice != "" {
		lines = append(lines, notice)
	}

	switch {
	case m.repos.err != nil:
		lines = append(lines, styleError.Render(m.fit(m.repos.err.Error())))
	case !m.repos.loaded:
		lines = append(lines, styleDim.Render(spinnerFrame(m.spinner)+" loading…"))
	case len(m.repos.list) == 0:
		lines = append(lines,
			styleDim.Render("nothing tracked yet — blast radius can only reach repositories on this list"),
			styleDim.Render("press a to add repositories from a GitHub user or organization"))
	default:
		lines = append(lines, styleFaint.Render(m.repoHeader()))
		start, end := window(m.repos.offset, m.repoRows(), len(m.repos.list))
		for i := start; i < end; i++ {
			lines = append(lines, m.repoRow(m.repos.list[i], i == m.repos.cursor))
		}
	}
	return panel(m.fit(title), strings.Join(lines, "\n"), m.width)
}

func (m Model) countStatus(status string) int {
	n := 0
	for _, t := range m.repos.list {
		if t.Status == status {
			n++
		}
	}
	return n
}

// repoNotice is the line above the list: a confirmation prompt, or the
// outcome of the last action.
func (m Model) repoNotice() string {
	if m.repos.mode == repoConfirmRemove {
		if repo, ok := m.repos.selected(); ok {
			return styleError.Render(m.fit("remove " + repo.FullName + " and its edges from the graph? y / n"))
		}
	}
	if m.repos.notice == "" {
		return ""
	}
	if m.repos.noticeOK {
		return styleSelect.Render(m.fit(m.repos.notice))
	}
	return styleError.Render(m.fit(m.repos.notice))
}

// repoNameWidth fits the longest name, within limits: a column sized to the
// panel would push the scan time and any error off the right-hand edge.
func (m Model) repoNameWidth() int {
	longest := len("REPOSITORY")
	for _, t := range m.repos.list {
		longest = max(longest, runewidth.StringWidth(t.FullName))
	}
	room := m.innerWidth() - colMarker - colRepoStatus - colRepoDeps - colRepoRisk - colRepoWhen - 4
	return clamp(longest, 8, max(8, min(room, m.innerWidth()/2)))
}

func (m Model) repoHeader() string {
	return m.fit("  " + pad("REPOSITORY", m.repoNameWidth()) + " " + pad("STATUS", colRepoStatus) +
		" " + pad("DEPS", colRepoDeps) + " " + pad("RISK", colRepoRisk) + " " + "SCANNED")
}

func (m Model) repoRow(t model.TrackedRepository, selected bool) string {
	name := pad(truncate(t.FullName, m.repoNameWidth()), m.repoNameWidth())
	status := pad(t.Status, colRepoStatus)
	deps := pad(fmt.Sprintf("%d", t.DependencyCount), colRepoDeps)
	when := ago(t.LastScanAt, time.Now())
	if t.Status == model.ScanFailed && t.LastError != "" {
		when += "  " + model.OneLine(t.LastError)
	}
	tail := truncate(when, max(0, m.innerWidth()-colMarker-m.repoNameWidth()-colRepoStatus-colRepoDeps-colRepoRisk-4))
	riskText, riskStyle := riskLabel(t)
	risk := pad(truncate(riskText, colRepoRisk), colRepoRisk)

	if selected {
		return styleSelect.Render("▸ " + name + " " + status + " " + deps + " " + risk + " " + tail)
	}
	return "  " + name + " " + statusStyle(t.Status).Render(status) + " " + styleDim.Render(deps) + " " +
		riskStyle.Render(risk) + " " + styleDim.Render(tail)
}

func (m Model) pickerView() string {
	r := m.repos
	title := "Add from " + r.pickOwner
	switch {
	case r.discovering:
		return panel(m.fit(title), styleDim.Render(spinnerFrame(m.spinner)+" listing "+r.pickOwner+"'s repositories…"), m.width)
	case r.tracking:
		title += "  ·  " + spinnerFrame(m.spinner) + " adding…"
	default:
		title += fmt.Sprintf("  %d repositories  ·  %d selected", len(r.discovered), len(r.pickedNames()))
	}

	lines := make([]string, 0, m.repoRows()+2)
	if notice := m.repoNotice(); notice != "" {
		lines = append(lines, notice)
	}
	nameWidth := m.pickNameWidth()
	lines = append(lines, styleFaint.Render(m.fit("      "+pad("REPOSITORY", nameWidth)+" "+
		pad("★", colPickStars)+" "+pad("LANGUAGE", colPickLang)+" DESCRIPTION")))

	start, end := window(r.pickOffset, m.repoRows(), len(r.discovered))
	for i := start; i < end; i++ {
		lines = append(lines, m.pickRow(r.discovered[i], i == r.pickCursor))
	}
	return panel(m.fit(title), strings.Join(lines, "\n"), m.width)
}

func (m Model) pickNameWidth() int {
	return clamp(m.innerWidth()/3, 12, 40)
}

func (m Model) pickRow(d model.DiscoveredRepository, selected bool) string {
	mark := "[ ] "
	switch {
	case d.Tracked:
		mark = "[✓] " // already tracked: shown, not selectable
	case m.repos.picked[d.FullName]:
		mark = "[x] "
	}
	name := d.FullName
	if d.Fork {
		name += " (fork)"
	}
	if d.Archived {
		name += " (archived)"
	}
	nameWidth := m.pickNameWidth()
	cols := pad(truncate(name, nameWidth), nameWidth) + " " +
		pad(compact(d.Stars), colPickStars) + " " +
		pad(truncate(d.Language, colPickLang), colPickLang) + " "
	desc := truncate(model.OneLine(d.Description), max(0, m.innerWidth()-colMarker-colPickMark-runewidth.StringWidth(cols)))

	switch {
	case selected:
		return styleSelect.Render("▸ " + mark + cols + desc)
	case d.Tracked:
		return "  " + styleFaint.Render(mark+cols+desc)
	default:
		return "  " + mark + cols + styleDim.Render(desc)
	}
}

// ago renders how long ago t was, compactly: "just now", "4m ago", "3h ago".
func ago(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// compact renders a star count as 950, 12.4k, 1.2M.
func compact(n int) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	case n >= 10_000:
		return fmt.Sprintf("%dk", n/1000)
	case n >= 1000:
		return fmt.Sprintf("%.1fk", float64(n)/1000)
	default:
		return fmt.Sprintf("%d", n)
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// updateFindingKeys handles the findings view. Tab switching and quitting
// fall through to the global keys.
func (m Model) updateFindingKeys(msg tea.KeyMsg) (Model, tea.Cmd, bool) {
	switch msg.String() {
	case "esc", "backspace", "left", "h":
		m.repos.mode = repoList
		return m, nil, true
	case "enter":
		if f, ok := m.repos.selectedFinding(); ok {
			next, cmd := m.open(f.Vulnerability)
			return next, cmd, true
		}
		return m, nil, true
	case "b":
		if f, ok := m.repos.selectedFinding(); ok {
			next, cmd := m.open(f.Vulnerability)
			next.tab = TabGraph
			return next, cmd, true
		}
		return m, nil, true
	case "u":
		// Findings the declared versions rule out are hidden by default;
		// showing them is how to see what version matching removed.
		m.repos.showUnaffected = !m.repos.showUnaffected
		m.repos.exposureLoading = true
		return m, tea.Batch(m.loadExposure(m.repos.exposureFor, m.repos.showUnaffected), m.spin()), true
	case "r":
		m.repos.exposureLoading = true
		return m, tea.Batch(m.loadExposure(m.repos.exposureFor, m.repos.showUnaffected), m.spin()), true
	case "j", "down":
		m.repos.findCursor++
		return m, nil, true
	case "k", "up":
		m.repos.findCursor--
		return m, nil, true
	case "g", "home":
		m.repos.findCursor = 0
		return m, nil, true
	case "G", "end":
		m.repos.findCursor = len(m.repos.exposure.Findings) - 1
		return m, nil, true
	case "pgdown", "ctrl+d":
		m.repos.findCursor += max(1, m.findingRows()-1)
		return m, nil, true
	case "pgup", "ctrl+u":
		m.repos.findCursor -= max(1, m.findingRows()-1)
		return m, nil, true
	}
	return m, nil, false
}

// Columns of the findings view.
const colVerdict = 9

// findingsView lists one repository's vulnerabilities, worst first.
func (m Model) findingsView() string {
	exp := m.repos.exposure
	name := m.repos.exposureFor

	title := "Findings  " + name
	switch {
	case m.repos.exposureLoading:
		title += "  ·  " + spinnerFrame(m.spinner) + " loading…"
	case m.repos.showUnaffected:
		title += fmt.Sprintf("  ·  %d, including those ruled out by version", len(exp.Findings))
	default:
		title += fmt.Sprintf("  ·  %d it may be exposed to", len(exp.Findings))
	}

	var lines []string
	switch {
	case m.repos.exposureErr != nil:
		lines = append(lines, styleError.Render(m.fit("couldn't load findings: "+m.repos.exposureErr.Error())))
	case m.repos.exposureLoading && len(exp.Findings) == 0:
		lines = append(lines, styleDim.Render(spinnerFrame(m.spinner)+" walking the dependency graph…"))
	case !exp.Scanned && !m.repos.exposureLoading:
		lines = append(lines,
			styleDim.Render(m.fit("not scanned yet — its dependencies have not been read, so its findings are unknown, not none")))
	case len(exp.Findings) == 0:
		msg := "nothing it depends on is affected by a known advisory"
		if exp.Summary.Total == 0 && !m.repos.showUnaffected {
			msg += " — press u to see findings its versions rule out"
		}
		lines = append(lines, styleSelect.Render(m.fit(msg)))
	default:
		lines = append(lines, styleDim.Render(m.fit(summaryLine(exp.Summary))))
		lines = append(lines, styleFaint.Render(m.fit("  "+pad("VERDICT", colVerdict)+" "+pad("SEVERITY", colSeverity)+" "+
			pad("FINDING", colID)+" "+"PACKAGE  DECLARED → AFFECTED  ·  TITLE")))
		start, end := window(m.repos.findOffset, m.findingRows(), len(exp.Findings))
		for i := start; i < end; i++ {
			lines = append(lines, m.findingRow(exp.Findings[i], i == m.repos.findCursor))
		}
	}
	return panel(m.fit(title), strings.Join(lines, "\n"), m.width)
}

// summaryLine says what the flag in the list is made of.
func summaryLine(s model.ExposureSummary) string {
	return fmt.Sprintf("critical: %d affected, %d possible  ·  high: %d affected, %d possible  ·  %d in all",
		s.CriticalAffected, s.CriticalPossible, s.HighAffected, s.HighPossible, s.Total)
}

func (m Model) findingRow(f model.RepositoryFinding, selected bool) string {
	verdict := pad(verdictLabel(f.Verdict), colVerdict)
	severity := f.Vulnerability.SeverityLabel()
	if f.Vulnerability.IsMalware() {
		severity = labelMalware
	}
	sev := pad(severity, colSeverity)
	id := pad(truncate(f.Vulnerability.CVEID, colID), colID)
	rest := f.Package + " " + f.DeclaredVersion + " → " + f.AffectedVersions
	if title := model.OneLine(f.Vulnerability.Headline()); title != "" {
		rest += "  ·  " + title
	}
	rest = truncate(rest, max(0, m.innerWidth()-colMarker-colVerdict-colSeverity-colID-3))

	if selected {
		return styleSelect.Render("▸ " + verdict + " " + sev + " " + id + " " + rest)
	}
	return "  " + verdictStyle(f.Verdict).Render(verdict) + " " + severityStyle(severity).Render(sev) + " " +
		styleCVE.Render(id) + " " + rest
}

// verdictLabel is how a verdict reads in a column.
func verdictLabel(v string) string {
	switch v {
	case model.VerdictAffected:
		return "AFFECTED"
	case model.VerdictPossiblyAffected:
		return "POSSIBLE"
	case model.VerdictNotAffected:
		return "RULED OUT"
	case model.VerdictUnknown:
		return "UNKNOWN"
	default:
		return "—"
	}
}

// riskLabel is the flag beside a tracked repository: its critical and high
// findings, or "clean", or "—" when nothing could be judged.
func riskLabel(t model.TrackedRepository) (string, lipgloss.Style) {
	e := t.Exposure
	switch {
	case !e.Computed:
		return "—", styleFaint
	case e.Critical() > 0 && e.High() > 0:
		return fmt.Sprintf("▲ %d crit %d high", e.Critical(), e.High()), severityStyle("CRITICAL")
	case e.Critical() > 0:
		return fmt.Sprintf("▲ %d critical", e.Critical()), severityStyle("CRITICAL")
	case e.High() > 0:
		return fmt.Sprintf("▲ %d high", e.High()), severityStyle("HIGH")
	case e.Total > 0:
		return fmt.Sprintf("%d lower", e.Total), styleDim
	default:
		return "clean", severityStyle("LOW")
	}
}
