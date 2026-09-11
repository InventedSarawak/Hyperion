package tui

import (
	"fmt"
	"strings"

	"github.com/mattn/go-runewidth"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// detailsView renders the finding open in the Details tab: everything known
// about it, top to bottom, scrollable like the tree.
func (m Model) detailsView() string {
	if m.detail.CVEID == "" {
		return panel("Details", styleDim.Render("select a finding in the Live Feed and press enter"), m.width)
	}

	lines := m.detailLines()
	start, end := window(m.detailOffset, m.bodyRows(), len(lines))

	title := "Details  " + m.detail.CVEID
	switch {
	case m.detailLoading:
		title += "  ·  " + spinnerFrame(m.spinner) + " loading full record…"
	case end-start < len(lines):
		title += fmt.Sprintf("  ·  lines %d–%d of %d", start+1, end, len(lines))
	}
	return panel(m.fit(title), strings.Join(lines[start:end], "\n"), m.width)
}

// detailLines lays the finding out as display lines, each already fitted to
// the panel, so scrolling and the height budget can count them.
func (m Model) detailLines() []string {
	v := m.detail
	width := m.innerWidth()
	if m.width <= 0 {
		width = 100
	}

	var out []string
	add := func(styled string) { out = append(out, styled) }
	blank := func() {
		if len(out) > 0 && out[len(out)-1] != "" {
			out = append(out, "")
		}
	}
	section := func(name string) {
		blank()
		add(styleTitle.Render(name))
	}

	// Headline: id, rating, and the title (or, when there is none, nothing —
	// the description follows in full below, so repeating it here would be
	// the same text twice).
	severity := v.SeverityLabel()
	score := ""
	if top, ok := v.TopScore(); ok && top.BaseScore > 0 {
		score = fmt.Sprintf(" %.1f", top.BaseScore)
	}
	add(styleCVE.Render(truncate(v.CVEID, width/2)) + "  " + severityStyle(severity).Render(severity+score))
	if title := model.OneLine(v.Title); title != "" {
		for _, line := range wrap(title, width) {
			add(styleTitle.Render(line))
		}
	}
	if m.detailErr != nil {
		add(styleError.Render(truncate("couldn't load the full record: "+m.detailErr.Error(), width)))
	}

	blank()
	add(field("Published", dateOrDash(v.PublishedAt.IsZero(), v.PublishedAt.Format("2006-01-02")), width))
	add(field("Modified", dateOrDash(v.ModifiedAt.IsZero(), v.ModifiedAt.Format("2006-01-02")), width))
	if len(v.Sources) > 0 {
		add(field("Reported by", strings.Join(v.Sources, ", "), width))
	}

	if len(v.Scores) > 0 {
		section("Scores")
		for _, s := range v.Scores {
			label := "CVSS " + s.Version
			if s.Version == "" {
				label = "rating"
			}
			line := fmt.Sprintf("  %-9s %4s  %-8s %s", label, scoreText(s.BaseScore), strings.ToUpper(s.Severity), s.Vector)
			add(truncate(line, width))
		}
	}

	section("Affected packages")
	if len(v.AffectedPackages) == 0 {
		add(styleDim.Render(truncate("  none named — no feed has linked this finding to a library,", width)))
		add(styleDim.Render(truncate("  so its blast radius cannot be computed", width)))
	} else {
		nameWidth := 0
		for _, p := range v.AffectedPackages {
			nameWidth = max(nameWidth, runewidth.StringWidth(p.Package))
		}
		nameWidth = min(nameWidth, width/2)
		for _, p := range v.AffectedPackages {
			versions := p.VersionRange
			if versions == "" {
				versions = "versions not stated"
				if m.detailLoading {
					versions = "…"
				}
			}
			add(truncate("  "+pad(truncate(p.Package, nameWidth), nameWidth)+"  "+versions, width))
		}
	}

	section("Description")
	if strings.TrimSpace(v.Description) == "" {
		add(styleDim.Render("  no description"))
	}
	paras := paragraphs(v.Description)
	for i, paragraph := range paras {
		for _, line := range wrap(paragraph, width-2) {
			add("  " + line)
		}
		// Consecutive list items stay together; anything else is spaced.
		if i+1 < len(paras) && !(isListItem(paragraph) && isListItem(paras[i+1])) {
			blank()
		}
	}

	if len(v.References) > 0 {
		section(fmt.Sprintf("References (%d)", len(v.References)))
		for _, ref := range v.References {
			add(styleDim.Render(truncate("  "+model.OneLine(ref), width)))
		}
	}

	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	return out
}

// field renders "Label       value" with the labels aligned. Only the value
// is truncated: measuring a styled string would count its escape codes.
func field(label, value string, width int) string {
	const labelWidth = 12
	return styleDim.Render(pad(label, labelWidth)) + truncate(model.OneLine(value), max(0, width-labelWidth))
}

func dateOrDash(zero bool, s string) string {
	if zero {
		return "—"
	}
	return s
}

func scoreText(score float64) string {
	if score <= 0 {
		return "—"
	}
	return fmt.Sprintf("%.1f", score)
}

// paragraphs splits a description into paragraphs, flattening each to one
// line. Advisory text arrives hard-wrapped at arbitrary widths and often as
// Markdown; re-flowing it to the terminal is what makes it readable. A blank
// line separates paragraphs, and Markdown headings and list items start new
// ones so their structure survives the re-flow.
func paragraphs(text string) []string {
	var (
		out     []string
		current []string
	)
	flush := func() {
		if len(current) > 0 {
			out = append(out, model.OneLine(strings.Join(current, " ")))
			current = nil
		}
	}
	for _, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "#"), strings.HasPrefix(line, "- "), strings.HasPrefix(line, "* "),
			strings.HasPrefix(line, "|"), strings.HasPrefix(line, "```"):
			flush()
			current = append(current, line)
			flush()
		default:
			current = append(current, line)
		}
	}
	flush()
	return out
}

func isListItem(p string) bool { return strings.HasPrefix(p, "- ") || strings.HasPrefix(p, "* ") }

// wrap breaks text into lines of at most width cells, at spaces where it can
// and mid-word where a single word is wider than the line (a long URL).
func wrap(text string, width int) []string {
	if width <= 0 {
		return nil
	}
	var (
		lines []string
		line  strings.Builder
		used  int
	)
	emit := func() {
		lines = append(lines, line.String())
		line.Reset()
		used = 0
	}
	for _, word := range strings.Fields(text) {
		w := runewidth.StringWidth(word)
		for w > width {
			if used > 0 {
				emit()
			}
			head := runewidth.Truncate(word, width, "")
			if head == "" {
				// A character wider than the whole line: take it anyway,
				// or this loop never advances.
				head = string([]rune(word)[:1])
			}
			lines = append(lines, head)
			word = word[len(head):]
			w = runewidth.StringWidth(word)
		}
		if w == 0 {
			continue
		}
		if used > 0 && used+1+w > width {
			emit()
		}
		if used > 0 {
			line.WriteByte(' ')
			used++
		}
		line.WriteString(word)
		used += w
	}
	if used > 0 {
		emit()
	}
	return lines
}
