// Package tui is deck's INBOUND adapter: a Bubble Tea terminal application
// driving the application use cases. It holds view state and key handling
// only — every question it answers comes from a use case behind a port.
package tui

import (
	"context"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// Tab identifies which view is on screen.
type Tab int

// The two views v2 ships: the live feed and the graph explorer.
const (
	TabFeed Tab = iota
	TabGraph
)

// Title is the tab's label in the header.
func (t Tab) Title() string {
	if t == TabGraph {
		return "Graph Explorer"
	}
	return "Live Feed"
}

// Searcher runs the feed query (consumer-side interface).
type Searcher interface {
	Handle(ctx context.Context, query string, pageSize int) (model.Feed, error)
}

// BlastRadiusExplorer walks the dependency graph (consumer-side interface).
type BlastRadiusExplorer interface {
	Handle(ctx context.Context, cveID string, maxDepth int) (model.BlastRadius, error)
}

// Options configure the model at construction.
type Options struct {
	Query           string
	PageSize        int
	MaxDepth        int
	RefreshInterval time.Duration
	Endpoint        string
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
	// line. Both are kept in range by clampScroll after every message.
	offset      int
	graphOffset int

	query   string
	editing bool

	loading     bool
	spinner     int
	err         error
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
	return Model{
		search:   search,
		explorer: explorer,
		opts:     opts,
		query:    opts.Query,
		loading:  true,
	}
}

// --- messages ---

// feedMsg carries the result of a feed refresh.
type feedMsg struct {
	feed model.Feed
	err  error
}

// radiusMsg carries the result of a graph traversal.
type radiusMsg struct {
	radius model.BlastRadius
	err    error
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

func (m Model) refresh() tea.Cmd {
	query, pageSize, search := m.query, m.opts.PageSize, m.search
	return func() tea.Msg {
		feed, err := search.Handle(context.Background(), query, pageSize)
		return feedMsg{feed: feed, err: err}
	}
}

func (m Model) explore(cveID string) tea.Cmd {
	depth, explorer := m.opts.MaxDepth, m.explorer
	return func() tea.Msg {
		radius, err := explorer.Handle(context.Background(), cveID, depth)
		return radiusMsg{radius: radius, err: err}
	}
}

func (m Model) tick() tea.Cmd {
	return tea.Tick(m.opts.RefreshInterval, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// Init starts the first refresh, the polling timer, and the spinner.
func (m Model) Init() tea.Cmd { return tea.Batch(m.refresh(), m.tick(), m.spin()) }

// Selected returns the vulnerability under the cursor, if any.
func (m Model) Selected() (model.Vulnerability, bool) {
	if m.cursor < 0 || m.cursor >= len(m.feed.Hits) {
		return model.Vulnerability{}, false
	}
	return m.feed.Hits[m.cursor].Vulnerability, true
}
