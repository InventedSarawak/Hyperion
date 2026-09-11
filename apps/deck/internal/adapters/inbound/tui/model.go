// Package tui is deck's INBOUND adapter: a Bubble Tea terminal application
// driving the application use cases. It holds view state and key handling
// only — every question it answers comes from a use case behind a port.
package tui

import (
	"context"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// Tab identifies which view is on screen.
type Tab int

// The four views, in the order they appear in the tab bar. A finding is read
// left to right: find it in the feed, read it in Details, see who it reaches in
// the Graph Explorer. Repositories decides what the graph can reach at all.
const (
	TabFeed Tab = iota
	TabDetails
	TabGraph
	TabRepos
)

// allTabs is the tab bar, in order.
var allTabs = []Tab{TabFeed, TabDetails, TabGraph, TabRepos}

// Title is the tab's label in the header.
func (t Tab) Title() string {
	switch t {
	case TabDetails:
		return "Details"
	case TabGraph:
		return "Graph Explorer"
	case TabRepos:
		return "Repositories"
	default:
		return "Live Feed"
	}
}

// Short is the tab's label in a narrow terminal.
func (t Tab) Short() string {
	switch t {
	case TabDetails:
		return "Details"
	case TabGraph:
		return "Graph"
	case TabRepos:
		return "Repos"
	default:
		return "Feed"
	}
}

// Searcher loads the feed a page at a time (consumer-side interface).
type Searcher interface {
	// Handle loads the first page. An empty query is the live feed; malware
	// is left out unless includeMalware is set.
	Handle(ctx context.Context, query string, sort model.SearchSort, includeMalware bool, pageSize int) (model.Feed, error)
	// More loads the page after feed's last and appends it.
	More(ctx context.Context, feed model.Feed, pageSize int) (model.Feed, error)
}

// BlastRadiusExplorer walks the dependency graph (consumer-side interface).
type BlastRadiusExplorer interface {
	Handle(ctx context.Context, cveID string, maxDepth int) (model.BlastRadius, error)
}

// VulnerabilityLoader fetches one finding in full (consumer-side interface).
type VulnerabilityLoader interface {
	Handle(ctx context.Context, id string) (model.Vulnerability, error)
}

// RepositoryManager reads and edits the watchlist (consumer-side interface).
type RepositoryManager interface {
	Tracked(ctx context.Context) ([]model.TrackedRepository, error)
	Discover(ctx context.Context, owner string) ([]model.DiscoveredRepository, error)
	Track(ctx context.Context, fullNames []string) ([]model.TrackedRepository, error)
	Untrack(ctx context.Context, fullName string) error
}

// Options configure the model at construction. Details and Repositories are
// optional: without them the Details tab shows what the search result
// carried, and the Repositories tab says it is not connected.
type Options struct {
	Query           string
	PageSize        int
	MaxDepth        int
	RefreshInterval time.Duration
	Endpoint        string

	Details      VulnerabilityLoader
	Repositories RepositoryManager
	Findings     RepositoryFindingsLoader
}

// RepositoryFindingsLoader lists the vulnerabilities one repository has
// (consumer-side interface).
type RepositoryFindingsLoader interface {
	Handle(ctx context.Context, fullName string, includeUnaffected bool) (model.RepositoryExposure, error)
}

// Model is the Bubble Tea state.
type Model struct {
	search   Searcher
	explorer BlastRadiusExplorer
	opts     Options

	tab    Tab
	feed   model.Feed
	cursor int
	radius model.BlastRadius

	// offset is the first feed row on screen; graphOffset the first tree
	// line; detailOffset the first details line. All are kept in range by
	// clampScroll after every message.
	offset       int
	graphOffset  int
	detailOffset int

	// detail is the finding open in the Details tab. It starts as the search
	// hit — so the tab has something to show at once — and is replaced by the
	// full record when that arrives.
	detail        model.Vulnerability
	detailLoading bool
	detailErr     error

	// radiusLoading and radiusErr belong to the graph alone, so a slow or
	// failed traversal never blanks the feed or the details.
	radiusLoading bool
	radiusErr     error

	repos repoState

	// query is the search box's text, which changes as the user types;
	// active is the query last submitted, which is what refreshes use. Using
	// the draft would let a poll fire a search for a half-typed term.
	query   string
	active  string
	sort    model.SearchSort
	malware bool // include malicious packages in the feed
	editing bool

	// loadingMore is a following page in flight. It is separate from loading
	// so the list stays on screen while the next page arrives.
	loadingMore bool
	moreErr     error
	// generation counts list replacements. A page is fetched against one
	// generation of the list; if the list was replaced before it arrived,
	// appending it would be wrong — the offsets it was fetched at no longer
	// line up, so findings would be skipped or repeated.
	generation int

	loading     bool // the feed's first page is in flight
	spinner     int
	err         error // the feed's last failure
	lastRefresh time.Time
	width       int
	height      int
	quitting    bool
}

// New builds the model. The feed is empty until the first refresh returns.
func New(search Searcher, explorer BlastRadiusExplorer, opts Options) Model {
	if opts.RefreshInterval <= 0 {
		opts.RefreshInterval = 30 * time.Second
	}
	if opts.PageSize <= 0 {
		opts.PageSize = 25
	}
	sort := model.SortRelevance
	if strings.TrimSpace(opts.Query) == "" {
		sort = model.SortNewest // no query: the live feed, newest first
	}
	return Model{
		search:   search,
		explorer: explorer,
		opts:     opts,
		query:    opts.Query,
		active:   opts.Query,
		sort:     sort,
		loading:  true,
	}
}

// busy reports whether anything is in flight, which is what keeps the
// spinner turning.
func (m Model) busy() bool {
	return m.loading || m.loadingMore || m.detailLoading || m.radiusLoading || m.repos.busy()
}

// --- messages ---

// feedMsg carries a first page: a new query, or a refresh of the current one.
type feedMsg struct {
	feed model.Feed
	err  error
	// keep is the CVE that was selected when a refresh was issued, so the
	// selection stays on the same finding when newer ones push it down.
	keep string
}

// moreMsg carries the feed with its next page appended.
type moreMsg struct {
	feed model.Feed
	err  error
	// generation is the list generation the page was fetched against. A
	// page token alone cannot tell stale from current: a refresh over
	// unchanged data hands back the very same token.
	generation int
}

// radiusMsg carries the result of a graph traversal for one CVE.
type radiusMsg struct {
	cveID  string
	radius model.BlastRadius
	err    error
}

// detailMsg carries the full record of one finding.
type detailMsg struct {
	id  string
	v   model.Vulnerability
	err error
}

// tickMsg drives the polling refresh. The feed polls because v2 has no
// streaming transport yet; v3's Kafka pipeline is what makes it push.
type tickMsg time.Time

// spinnerMsg advances the working indicator. It is a separate, much faster
// timer than tickMsg, and it only re-arms while something is in flight — an
// idle deck should not wake the terminal ten times a second.
type spinnerMsg time.Time

// spinnerInterval is fast enough to read as motion, slow enough to be cheap.
const spinnerInterval = 100 * time.Millisecond

func (m Model) spin() tea.Cmd {
	return tea.Tick(spinnerInterval, func(t time.Time) tea.Msg { return spinnerMsg(t) })
}

// --- commands ---

// refresh re-runs the active query from the top. It asks for as many results
// as are already loaded (up to the per-request cap), so a periodic refresh
// updates what you have scrolled through instead of collapsing it to one page,
// and it keeps the selection on the same finding.
func (m Model) refresh() tea.Cmd {
	query, sort, malware, search := m.active, m.sort, m.malware, m.search
	size := clamp(len(m.feed.Hits), m.opts.PageSize, maxPageSize)
	keep := ""
	if v, ok := m.Selected(); ok {
		keep = v.CVEID
	}
	return func() tea.Msg {
		feed, err := search.Handle(context.Background(), query, sort, malware, size)
		return feedMsg{feed: feed, err: err, keep: keep}
	}
}

// fresh runs a new query from the top, with nothing to preserve.
func (m Model) fresh() tea.Cmd {
	query, sort, malware, size, search := m.active, m.sort, m.malware, m.opts.PageSize, m.search
	return func() tea.Msg {
		feed, err := search.Handle(context.Background(), query, sort, malware, size)
		return feedMsg{feed: feed, err: err}
	}
}

// more fetches the page after the last loaded one.
func (m Model) more() tea.Cmd {
	feed, size, search, generation := m.feed, m.opts.PageSize, m.search, m.generation
	return func() tea.Msg {
		next, err := search.More(context.Background(), feed, size)
		return moreMsg{feed: next, err: err, generation: generation}
	}
}

// maxPageSize is the most one request may ask for.
const maxPageSize = 200

func (m Model) explore(cveID string) tea.Cmd {
	depth, explorer := m.opts.MaxDepth, m.explorer
	return func() tea.Msg {
		radius, err := explorer.Handle(context.Background(), cveID, depth)
		return radiusMsg{cveID: cveID, radius: radius, err: err}
	}
}

func (m Model) loadDetail(id string) tea.Cmd {
	loader := m.opts.Details
	return func() tea.Msg {
		v, err := loader.Handle(context.Background(), id)
		return detailMsg{id: id, v: v, err: err}
	}
}

func (m Model) tick() tea.Cmd {
	return tea.Tick(m.opts.RefreshInterval, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// Init starts the first load, the polling timer, and the spinner.
func (m Model) Init() tea.Cmd { return tea.Batch(m.fresh(), m.tick(), m.spin()) }

// Selected returns the vulnerability under the cursor, if any.
func (m Model) Selected() (model.Vulnerability, bool) {
	if m.cursor < 0 || m.cursor >= len(m.feed.Hits) {
		return model.Vulnerability{}, false
	}
	return m.feed.Hits[m.cursor].Vulnerability, true
}

// open shows a finding in the Details tab and starts loading both its full
// record and its blast radius, so the Graph Explorer is usually ready by the
// time anyone switches to it.
func (m Model) open(v model.Vulnerability) (Model, tea.Cmd) {
	m.tab = TabDetails
	m.detail = v
	m.detailErr = nil
	m.detailOffset = 0

	cmds := []tea.Cmd{m.spin()}
	if m.opts.Details != nil {
		m.detailLoading = true
		cmds = append(cmds, m.loadDetail(v.CVEID))
	}
	m, cmd := m.startRadius(v.CVEID)
	return m, tea.Batch(append(cmds, cmd)...)
}

// startRadius begins a traversal for id. The previous result is cleared first
// so the graph never shows one CVE's radius under another CVE's heading while
// the request is in flight.
func (m Model) startRadius(id string) (Model, tea.Cmd) {
	m.radius = model.BlastRadius{CVEID: id}
	m.radiusErr = nil
	m.radiusLoading = true
	m.graphOffset = 0
	return m, m.explore(id)
}

// graphTarget is the finding the graph should show: the one open in Details,
// or failing that the one under the cursor.
func (m Model) graphTarget() (string, bool) {
	if m.detail.CVEID != "" {
		return m.detail.CVEID, true
	}
	if v, ok := m.Selected(); ok {
		return v.CVEID, true
	}
	return "", false
}
