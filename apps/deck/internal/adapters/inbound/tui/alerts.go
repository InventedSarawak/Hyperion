package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// alertMode is what the Alerts tab is doing.
type alertMode int

const (
	// alertList shows the rules in place.
	alertList alertMode = iota
	// alertNameInput, alertTermInput and alertSeverityPick are the three
	// steps of writing a new rule: what to call it, what text it matches,
	// how severe a finding must be.
	alertNameInput
	alertTermInput
	alertSeverityPick
	// alertConfirmDelete is waiting for y/n before removing a rule.
	alertConfirmDelete
	// alertRaised lists the alerts one rule — or every rule — has raised.
	alertRaised
)

// alertState is the Alerts tab: the rules, the alerts they raised, and the
// new-rule flow layered over them.
type alertState struct {
	mode alertMode

	rules   []model.AlertRule
	loaded  bool
	loading bool
	err     error
	cursor  int
	offset  int

	// The rule being written.
	name     string
	term     string
	severity int // index into model.Severities
	saving   bool

	// notice is a one-line outcome shown above the list.
	notice   string
	noticeOK bool

	// The alerts view. raisedFor is the rule shown; empty means every rule.
	raised        []model.Alert
	raisedFor     string
	raisedName    string
	raisedLoading bool
	raisedErr     error
	raisedCursor  int
	raisedOffset  int
}

func (a alertState) busy() bool { return a.loading || a.saving || a.raisedLoading }

// selected is the rule under the cursor.
func (a alertState) selected() (model.AlertRule, bool) {
	if a.cursor < 0 || a.cursor >= len(a.rules) {
		return model.AlertRule{}, false
	}
	return a.rules[a.cursor], true
}

// selectedAlert is the alert under the cursor in the alerts view.
func (a alertState) selectedAlert() (model.Alert, bool) {
	if a.raisedCursor < 0 || a.raisedCursor >= len(a.raised) {
		return model.Alert{}, false
	}
	return a.raised[a.raisedCursor], true
}

// --- messages ---

type rulesMsg struct {
	rules []model.AlertRule
	err   error
}

type ruleCreatedMsg struct {
	rule model.AlertRule
	err  error
}

type ruleDeletedMsg struct {
	id, name string
	err      error
}

type raisedMsg struct {
	ruleID string
	alerts []model.Alert
	err    error
}

// --- commands ---

func (m Model) loadRules() tea.Cmd {
	manager := m.opts.Alerts
	return func() tea.Msg {
		rules, err := manager.Rules(context.Background())
		return rulesMsg{rules: rules, err: err}
	}
}

func (m Model) createRule(name string, criteria model.Criteria) tea.Cmd {
	manager := m.opts.Alerts
	return func() tea.Msg {
		rule, err := manager.Create(context.Background(), name, criteria)
		return ruleCreatedMsg{rule: rule, err: err}
	}
}

func (m Model) deleteRule(rule model.AlertRule) tea.Cmd {
	manager := m.opts.Alerts
	return func() tea.Msg {
		return ruleDeletedMsg{id: rule.ID, name: rule.Name, err: manager.Delete(context.Background(), rule.ID)}
	}
}

func (m Model) loadRaised(ruleID string) tea.Cmd {
	manager := m.opts.Alerts
	return func() tea.Msg {
		alerts, err := manager.Alerts(context.Background(), ruleID)
		return raisedMsg{ruleID: ruleID, alerts: alerts, err: err}
	}
}

// enterAlerts loads the rules the first time the tab is opened.
func (m Model) enterAlerts() (Model, tea.Cmd) {
	if m.opts.Alerts == nil || m.alerts.loaded || m.alerts.loading {
		return m, nil
	}
	m.alerts.loading = true
	return m, tea.Batch(m.loadRules(), m.spin())
}

// openRaised shows what a rule has caught; an empty id shows every rule's.
func (m Model) openRaised(ruleID, name string) (Model, tea.Cmd) {
	m.alerts.mode = alertRaised
	if ruleID != m.alerts.raisedFor || name != m.alerts.raisedName {
		m.alerts.raised = nil
		m.alerts.raisedCursor, m.alerts.raisedOffset = 0, 0
	}
	m.alerts.raisedFor, m.alerts.raisedName = ruleID, name
	m.alerts.raisedErr = nil
	m.alerts.raisedLoading = true
	return m, tea.Batch(m.loadRaised(ruleID), m.spin())
}

// --- message handling ---

func (m Model) updateAlertMsg(msg tea.Msg) (Model, tea.Cmd) {
	switch msg := msg.(type) {
	case rulesMsg:
		m.alerts.loading = false
		m.alerts.err = msg.err
		if msg.err == nil {
			keep, _ := m.alerts.selected()
			m.alerts.rules = msg.rules
			m.alerts.loaded = true
			for i, r := range m.alerts.rules {
				if r.ID == keep.ID {
					m.alerts.cursor = i
				}
			}
		}
		return m, nil

	case ruleCreatedMsg:
		m.alerts.saving = false
		if msg.err != nil {
			// Back to the step that can fix it, with what was typed intact:
			// a rejected rule should not cost the reader their typing.
			m.alerts.notice, m.alerts.noticeOK = "couldn't add the rule: "+msg.err.Error(), false
			return m, nil
		}
		m.alerts.mode = alertList
		m.alerts.rules = append(m.alerts.rules, msg.rule)
		m.alerts.cursor = len(m.alerts.rules) - 1
		// Said outright, because it is the first thing anyone expects to work
		// differently: a new rule does not look back through history.
		m.alerts.notice, m.alerts.noticeOK = fmt.Sprintf(
			"added %q — it alerts on findings that arrive from now on", msg.rule.Name), true
		return m, nil

	case ruleDeletedMsg:
		m.alerts.saving = false
		m.alerts.mode = alertList
		if msg.err != nil {
			m.alerts.notice, m.alerts.noticeOK = "couldn't remove "+msg.name+": "+msg.err.Error(), false
			return m, nil
		}
		kept := m.alerts.rules[:0:0]
		for _, r := range m.alerts.rules {
			if r.ID != msg.id {
				kept = append(kept, r)
			}
		}
		m.alerts.rules = kept
		m.alerts.notice, m.alerts.noticeOK = fmt.Sprintf("removed %q and the alerts it raised", msg.name), true
		return m, nil

	case raisedMsg:
		if msg.ruleID != m.alerts.raisedFor {
			return m, nil // a different rule has been opened since
		}
		m.alerts.raisedLoading = false
		m.alerts.raisedErr = msg.err
		if msg.err == nil {
			m.alerts.raised = msg.alerts
		}
		return m, nil
	}
	return m, nil
}

// --- keys ---

// typingAlert reports whether keystrokes belong to the new-rule prompt.
func (m Model) typingAlert() bool {
	return m.tab == TabAlerts && (m.alerts.mode == alertNameInput || m.alerts.mode == alertTermInput)
}

// updateAlertInput handles keys while a rule's name or term is being typed.
func (m Model) updateAlertInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	field := &m.alerts.name
	if m.alerts.mode == alertTermInput {
		field = &m.alerts.term
	}
	switch msg.Type {
	case tea.KeyEnter:
		if m.alerts.mode == alertNameInput {
			if strings.TrimSpace(m.alerts.name) == "" {
				return m, nil
			}
			m.alerts.mode = alertTermInput
			return m, nil
		}
		// An empty term is allowed here: a rule can be about severity alone.
		m.alerts.mode = alertSeverityPick
		return m, nil
	case tea.KeyEsc:
		m.alerts.mode = alertList
		m.alerts.notice = ""
		return m, nil
	case tea.KeyBackspace:
		if runes := []rune(*field); len(runes) > 0 {
			*field = string(runes[:len(runes)-1])
		}
		return m, nil
	case tea.KeyCtrlC:
		m.quitting = true
		return m, tea.Quit
	case tea.KeySpace:
		*field += " "
		return m, nil
	case tea.KeyRunes:
		*field += string(msg.Runes)
		return m, nil
	}
	return m, nil
}

// updateAlertKeys handles the Alerts tab's own keys. It reports false for keys
// it does not use, so the global ones (tab, q, 1–5) still work.
func (m Model) updateAlertKeys(msg tea.KeyMsg) (Model, tea.Cmd, bool) {
	if m.opts.Alerts == nil {
		return m, nil, false
	}
	switch m.alerts.mode {
	case alertSeverityPick:
		return m.updateSeverityPick(msg)
	case alertConfirmDelete:
		if rule, ok := m.alerts.selected(); ok && (msg.String() == "y" || msg.String() == "Y") {
			m.alerts.saving = true
			return m, tea.Batch(m.deleteRule(rule), m.spin()), true
		}
		m.alerts.mode = alertList
		m.alerts.notice = ""
		return m, nil, true
	case alertRaised:
		return m.updateRaisedKeys(msg)
	}

	switch msg.String() {
	case "enter":
		if rule, ok := m.alerts.selected(); ok {
			next, cmd := m.openRaised(rule.ID, rule.Name)
			return next, cmd, true
		}
		return m, nil, true
	case "A":
		next, cmd := m.openRaised("", "")
		return next, cmd, true
	case "n", "a", "+":
		m.alerts.mode = alertNameInput
		m.alerts.name, m.alerts.term, m.alerts.severity = "", "", 0
		m.alerts.notice = ""
		return m, nil, true
	case "d", "x", "delete":
		if _, ok := m.alerts.selected(); ok {
			m.alerts.mode = alertConfirmDelete
		}
		return m, nil, true
	case "r":
		if !m.alerts.loading {
			m.alerts.loading = true
			return m, tea.Batch(m.loadRules(), m.spin()), true
		}
		return m, nil, true
	case "j", "down":
		m.alerts.cursor++
		return m, nil, true
	case "k", "up":
		m.alerts.cursor--
		return m, nil, true
	case "g", "home":
		m.alerts.cursor = 0
		return m, nil, true
	case "G", "end":
		m.alerts.cursor = len(m.alerts.rules) - 1
		return m, nil, true
	}
	return m, nil, false
}

// updateSeverityPick handles the last step of a new rule.
func (m Model) updateSeverityPick(msg tea.KeyMsg) (Model, tea.Cmd, bool) {
	switch msg.String() {
	case "j", "down", "l", "right":
		m.alerts.severity = min(m.alerts.severity+1, len(model.Severities)-1)
	case "k", "up", "h", "left":
		m.alerts.severity = max(m.alerts.severity-1, 0)
	case "esc":
		m.alerts.mode = alertList
		m.alerts.notice = ""
	case "enter":
		if m.alerts.saving {
			return m, nil, true
		}
		m.alerts.saving = true
		criteria := model.Criteria{Term: m.alerts.term, MinSeverity: model.Severities[m.alerts.severity]}
		return m, tea.Batch(m.createRule(m.alerts.name, criteria), m.spin()), true
	}
	return m, nil, true
}

// updateRaisedKeys handles keys while reading what a rule caught.
func (m Model) updateRaisedKeys(msg tea.KeyMsg) (Model, tea.Cmd, bool) {
	switch msg.String() {
	case "esc":
		m.alerts.mode = alertList
		return m, nil, true
	case "enter", "b":
		alert, ok := m.alerts.selectedAlert()
		if !ok {
			return m, nil, true
		}
		// The alert's finding opens in Details like any other, so its blast
		// radius is one keypress away — which is the next question anyone
		// asks about an alert.
		opened, cmd := m.open(alert.Vulnerability)
		if msg.String() == "b" {
			opened.tab = TabGraph
		}
		return opened, cmd, true
	case "r":
		if !m.alerts.raisedLoading {
			next, cmd := m.openRaised(m.alerts.raisedFor, m.alerts.raisedName)
			return next, cmd, true
		}
		return m, nil, true
	case "j", "down":
		m.alerts.raisedCursor++
		return m, nil, true
	case "k", "up":
		m.alerts.raisedCursor--
		return m, nil, true
	case "g", "home":
		m.alerts.raisedCursor = 0
		return m, nil, true
	case "G", "end":
		m.alerts.raisedCursor = len(m.alerts.raised) - 1
		return m, nil, true
	case "pgdown", "ctrl+d":
		m.alerts.raisedCursor += max(1, m.alertRows()-1)
		return m, nil, true
	case "pgup", "ctrl+u":
		m.alerts.raisedCursor -= max(1, m.alertRows()-1)
		return m, nil, true
	}
	return m, nil, false
}

// --- view ---

// colRuleName is the rule-name column. Names are short labels by nature.
const colRuleName = 24

func (m Model) alertsView() string {
	if m.opts.Alerts == nil {
		return panel("Alerts", styleDim.Render("not connected to a service that manages alert rules"), m.width)
	}
	if m.alerts.mode == alertRaised {
		return m.raisedView()
	}

	title := fmt.Sprintf("Alert rules  %d in place", len(m.alerts.rules))
	var lines []string
	if notice := m.alertNotice(); notice != "" {
		lines = append(lines, notice)
	}

	switch {
	case m.alerts.mode == alertSeverityPick:
		lines = append(lines, m.severityPicker()...)
	case m.alerts.err != nil:
		lines = append(lines, styleError.Render(m.fit(m.alerts.err.Error())))
	case !m.alerts.loaded:
		lines = append(lines, styleDim.Render(spinnerFrame(m.spinner)+" loading…"))
	case len(m.alerts.rules) == 0:
		lines = append(lines,
			styleDim.Render(m.fit("no alert rules yet — nothing can alert until one exists")),
			styleDim.Render(m.fit("press n to add one: a name, a term to match, and how severe it must be")),
			"",
			styleFaint.Render(m.fit("a rule alerts on findings that arrive after it is made, not on history")))
	default:
		lines = append(lines, styleFaint.Render(m.fit("  "+pad("RULE", colRuleName)+" "+pad("ADDED", 10)+" MATCHES")))
		start, end := window(m.alerts.offset, m.alertRows(), len(m.alerts.rules))
		for i := start; i < end; i++ {
			lines = append(lines, m.ruleRow(m.alerts.rules[i], i == m.alerts.cursor))
		}
	}
	return panel(m.fit(title), strings.Join(lines, "\n"), m.width)
}

func (m Model) ruleRow(r model.AlertRule, selected bool) string {
	name := pad(truncate(r.Name, colRuleName), colRuleName)
	added := pad(ago(r.CreatedAt, time.Now()), 10)
	criteria := truncate(r.Criteria.Summary(), max(0, m.innerWidth()-colMarker-colRuleName-10-2))
	if selected {
		return styleSelect.Render("▸ " + name + " " + added + " " + criteria)
	}
	return "  " + name + " " + styleDim.Render(added) + " " + criteria
}

// severityPicker is the last step of a new rule: one line per level.
func (m Model) severityPicker() []string {
	lines := []string{styleDim.Render(m.fit(fmt.Sprintf("new rule %q, matching %s", m.alerts.name, termLabel(m.alerts.term)))),
		styleFaint.Render("how severe must a finding be?")}
	for i, s := range model.Severities {
		label := model.SeverityChoice(s)
		if i == m.alerts.severity {
			lines = append(lines, styleSelect.Render("▸ "+label))
			continue
		}
		lines = append(lines, "  "+severityStyle(s).Render(label))
	}
	if m.alerts.saving {
		lines = append(lines, styleDim.Render(spinnerFrame(m.spinner)+" adding…"))
	}
	return lines
}

func termLabel(term string) string {
	if strings.TrimSpace(term) == "" {
		return "any text"
	}
	return fmt.Sprintf("%q", strings.TrimSpace(term))
}

func (m Model) alertNotice() string {
	if m.alerts.mode == alertConfirmDelete {
		if rule, ok := m.alerts.selected(); ok {
			return styleError.Render(m.fit(fmt.Sprintf("remove %q and the alerts it raised? y / n", rule.Name)))
		}
	}
	if m.alerts.notice == "" {
		return ""
	}
	if m.alerts.noticeOK {
		return styleSelect.Render(m.fit(m.alerts.notice))
	}
	return styleError.Render(m.fit(m.alerts.notice))
}

func (m Model) raisedView() string {
	scope := "every rule"
	if m.alerts.raisedFor != "" {
		scope = fmt.Sprintf("%q", m.alerts.raisedName)
	}
	title := fmt.Sprintf("Alerts  %s  ·  %d", scope, len(m.alerts.raised))

	var lines []string
	switch {
	case m.alerts.raisedErr != nil:
		lines = append(lines, styleError.Render(m.fit(m.alerts.raisedErr.Error())))
	case m.alerts.raisedLoading && len(m.alerts.raised) == 0:
		lines = append(lines, styleDim.Render(spinnerFrame(m.spinner)+" loading…"))
	case len(m.alerts.raised) == 0:
		lines = append(lines,
			styleDim.Render(m.fit("nothing has matched yet")),
			styleFaint.Render(m.fit("a rule only alerts on findings that arrive after it was made")))
	default:
		lines = append(lines, styleFaint.Render(m.fit("  "+pad("SEVERITY", colSeverity)+" "+pad("FINDING", colID)+" "+pad("WHEN", 10)+" WHY · WHAT")))
		start, end := window(m.alerts.raisedOffset, m.alertRows(), len(m.alerts.raised))
		for i := start; i < end; i++ {
			lines = append(lines, m.alertRow(m.alerts.raised[i], i == m.alerts.raisedCursor))
		}
	}
	return panel(m.fit(title), strings.Join(lines, "\n"), m.width)
}

func (m Model) alertRow(a model.Alert, selected bool) string {
	severity := a.Vulnerability.DisplayLabel()
	sev := pad(severity, colSeverity)
	id := pad(truncate(a.CVEID, colID), colID)
	when := pad(ago(a.CreatedAt, time.Now()), 10)
	rest := a.Reason
	if m.alerts.raisedFor == "" && a.RuleName != "" {
		// Across every rule, which rule is part of the answer.
		rest = a.RuleName + ": " + rest
	}
	if headline := model.OneLine(a.Vulnerability.Headline()); headline != "" && headline != a.CVEID {
		rest += "  ·  " + headline
	}
	rest = truncate(rest, max(0, m.innerWidth()-colMarker-colSeverity-colID-10-3))

	if selected {
		return styleSelect.Render("▸ " + sev + " " + id + " " + when + " " + rest)
	}
	return "  " + severityStyle(severity).Render(sev) + " " + styleCVE.Render(id) + " " + styleDim.Render(when) + " " + rest
}

func (m Model) alertHints() string {
	switch m.alerts.mode {
	case alertNameInput:
		return "  type a name · enter next · esc cancel"
	case alertTermInput:
		return "  text to match, or leave empty for any · enter next · esc cancel"
	case alertSeverityPick:
		return "  ↑/↓ choose · enter add the rule · esc cancel"
	case alertConfirmDelete:
		return "  y remove · n keep"
	case alertRaised:
		return "  ↑/↓ move · enter details · b blast radius · r refresh · esc back · q quit"
	}
	return "  ↑/↓ move · enter its alerts · A every alert · n new rule · d remove · r refresh · tab switch · q quit"
}

// alertPrompt is the prompt box while a rule's name or term is being typed.
func (m Model) alertPrompt() (label, text string, active bool) {
	switch m.alerts.mode {
	case alertNameInput:
		return "new rule name: ", m.alerts.name, true
	case alertTermInput:
		return "match text (optional): ", m.alerts.term, true
	}
	return "new rule: ", "press n", false
}
