package tui

import (
	"strconv"
	"strings"
	"sync"

	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/glamour/styles"
	"github.com/charmbracelet/x/ansi"
)

// markdownCacheLimit bounds the rendered-description cache. A session opens a
// few dozen findings; the bound only stops a long one growing without end.
const markdownCacheLimit = 128

var markdownCache = struct {
	sync.Mutex
	lines     map[string][]string
	renderers map[int]*glamour.TermRenderer
}{lines: map[string][]string{}, renderers: map[int]*glamour.TermRenderer{}}

// markdownLines renders an advisory description as display lines, each at
// most width cells wide and indented to line up with the panel's sections.
//
// Descriptions are Markdown more often than not — GitHub's advisories carry
// "### Impact" headings, bullet lists, code blocks and links — while NVD's
// plain text arrives hard-wrapped at arbitrary widths. Rendering reads both:
// soft line breaks re-flow, and structure keeps its shape without its markup.
//
// The style is fixed rather than detected. Detection asks the terminal for
// its background colour, and the reply arrives on stdin, where bubbletea
// reads it as keypresses. The result is cached, because View runs on every
// spinner tick and rendering is the most expensive thing the TUI does.
func markdownLines(text string, width int) []string {
	if width <= 0 {
		return nil
	}
	key := strconv.Itoa(width) + "\x00" + text

	markdownCache.Lock()
	defer markdownCache.Unlock()
	if lines, ok := markdownCache.lines[key]; ok {
		return lines
	}

	lines, err := renderMarkdown(text, width)
	if err != nil {
		lines = plainLines(text, width)
	}
	if len(markdownCache.lines) >= markdownCacheLimit {
		clear(markdownCache.lines)
	}
	markdownCache.lines[key] = lines
	return lines
}

// renderMarkdown runs the renderer for width. Callers hold the cache lock.
func renderMarkdown(text string, width int) ([]string, error) {
	r, ok := markdownCache.renderers[width]
	if !ok {
		var err error
		r, err = glamour.NewTermRenderer(
			glamour.WithStyles(styles.DarkStyleConfig),
			glamour.WithWordWrap(width),
			glamour.WithEmoji(),
		)
		if err != nil {
			return nil, err
		}
		markdownCache.renderers[width] = r
	}

	out, err := r.Render(text)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		lines = append(lines, fitLine(line, width)...)
	}
	return trimBlankLines(lines), nil
}

// fitLine breaks a line wider than width. Word wrap never breaks a word, so a
// long URL can still overrun the line, and a line the terminal wraps by
// itself moves every line below it and breaks the height budget. The pieces
// after the first keep the document's indent.
func fitLine(line string, width int) []string {
	if ansi.StringWidth(line) <= width {
		return []string{line}
	}
	const indent = "  "
	out := []string{ansi.Truncate(line, width, "")}
	rest := ansi.TruncateLeft(line, width, "")
	for _, piece := range strings.Split(ansi.Hardwrap(rest, width-len(indent), true), "\n") {
		if strings.TrimSpace(ansi.Strip(piece)) != "" {
			out = append(out, indent+piece)
		}
	}
	return out
}

// plainLines is the fallback when rendering fails: paragraphs re-flowed as
// plain text, list items kept together.
func plainLines(text string, width int) []string {
	var out []string
	paras := paragraphs(text)
	for i, paragraph := range paras {
		for _, line := range wrap(paragraph, width-2) {
			out = append(out, "  "+line)
		}
		if i+1 < len(paras) && !(isListItem(paragraph) && isListItem(paras[i+1])) {
			out = append(out, "")
		}
	}
	return out
}

// trimBlankLines drops the blank lines a rendered document opens and closes
// with; the panel spaces its own sections.
func trimBlankLines(lines []string) []string {
	blank := func(s string) bool { return strings.TrimSpace(ansi.Strip(s)) == "" }
	for len(lines) > 0 && blank(lines[0]) {
		lines = lines[1:]
	}
	for len(lines) > 0 && blank(lines[len(lines)-1]) {
		lines = lines[:len(lines)-1]
	}
	return lines
}
