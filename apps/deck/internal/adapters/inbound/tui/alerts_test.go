package tui_test

import (
	"context"
	"errors"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/adapters/inbound/tui"
	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// stubAlerts stands in for the alerting use case.
type stubAlerts struct {
	rules   []model.AlertRule
	alerts  map[string][]model.Alert // by rule id; "" is every rule
	created []model.Criteria
	deleted []string
	refuse  error
}

func (s *stubAlerts) Rules(context.Context) ([]model.AlertRule, error) { return s.rules, nil }
func (s *stubAlerts) Create(_ context.Context, name string, c model.Criteria) (model.AlertRule, error) {
	if s.refuse != nil {
		return model.AlertRule{}, s.refuse
	}
	s.created = append(s.created, c)
	r := model.AlertRule{ID: "rule_new", Name: name, Criteria: c, CreatedAt: time.Now()}
	s.rules = append(s.rules, r)
	return r, nil
}
func (s *stubAlerts) Delete(_ context.Context, id string) error {
	s.deleted = append(s.deleted, id)
	return nil
}
func (s *stubAlerts) Alerts(_ context.Context, ruleID string) ([]model.Alert, error) {
	return s.alerts[ruleID], nil
}

// alertsTab is a model on the Alerts tab with its rules loaded.
func alertsTab(stub *stubAlerts) tui.Model {
	GinkgoHelper()
	m := tui.New(&stubSearch{feed: manyHits(3)}, &stubExplorer{},
		tui.Options{PageSize: 25, Endpoint: "nexus", Alerts: stub})
	m, _ = apply(m, tea.WindowSizeMsg{Width: 120, Height: 40})
	m = settle(m, m.Init())
	m, cmd := apply(m, key("5"))
	return settle(m, cmd)
}

// typeText sends each rune as its own keypress, the way a person types.
func typeText(m tui.Model, s string) tui.Model {
	GinkgoHelper()
	for _, r := range s {
		if r == ' ' {
			m, _ = apply(m, tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}})
			continue
		}
		m, _ = apply(m, key(string(r)))
	}
	return m
}

func press(m tui.Model, k tea.KeyType) tui.Model {
	GinkgoHelper()
	m, cmd := apply(m, tea.KeyMsg{Type: k})
	return settle(m, cmd)
}

var log4j = model.AlertRule{ID: "rule_1", Name: "Log4j", CreatedAt: time.Now().Add(-time.Hour),
	Criteria: model.Criteria{Term: "log4j", MinSeverity: "HIGH"}}

var _ = Describe("The Alerts tab", func() {
	It("explains an empty list, including that rules do not look back", func() {
		view := stripANSI(alertsTab(&stubAlerts{}).View())
		Expect(view).To(ContainSubstring("▌ 5 Alerts"))
		Expect(view).To(ContainSubstring("no alert rules yet"))
		Expect(view).To(ContainSubstring("not on history"))
	})

	It("lists the rules with what each matches", func() {
		view := stripANSI(alertsTab(&stubAlerts{rules: []model.AlertRule{log4j}}).View())
		Expect(view).To(ContainSubstring("Log4j"))
		Expect(view).To(ContainSubstring(`"log4j" · high+`))
	})

	It("writes a new rule in three steps: name, text, severity", func() {
		stub := &stubAlerts{}
		m := alertsTab(stub)

		m, _ = apply(m, key("n"))
		m = typeText(m, "Next js")
		m = press(m, tea.KeyEnter)
		m = typeText(m, "next")
		m = press(m, tea.KeyEnter)
		Expect(stripANSI(m.View())).To(ContainSubstring("how severe must a finding be?"))

		m, _ = apply(m, key("j")) // low
		m, _ = apply(m, key("j")) // medium
		m, _ = apply(m, key("j")) // high
		m = press(m, tea.KeyEnter)

		Expect(stub.created).To(HaveLen(1))
		Expect(stub.created[0]).To(Equal(model.Criteria{Term: "next", MinSeverity: "HIGH"}))
		view := stripANSI(m.View())
		Expect(view).To(ContainSubstring("Next js"))
		Expect(view).To(ContainSubstring("from now on"), "a new rule says it does not look back")
	})

	It("keeps what was typed when the rule is refused", func() {
		stub := &stubAlerts{refuse: errors.New("give it a term or a severity")}
		m := alertsTab(stub)
		m, _ = apply(m, key("n"))
		m = typeText(m, "Everything")
		m = press(m, tea.KeyEnter)
		m = press(m, tea.KeyEnter)
		m = press(m, tea.KeyEnter)

		view := stripANSI(m.View())
		Expect(view).To(ContainSubstring("give it a term or a severity"))
		Expect(view).To(ContainSubstring(`new rule "Everything"`), "still on the step that can fix it")
	})

	It("treats letters as text while a name is typed, not as shortcuts", func() {
		// q quits and d deletes everywhere else; inside the prompt they are
		// just letters.
		m := alertsTab(&stubAlerts{rules: []model.AlertRule{log4j}})
		m, _ = apply(m, key("n"))
		m = typeText(m, "qd")
		Expect(stripANSI(m.View())).To(ContainSubstring("new rule name: qd"))
	})

	It("shows what a rule caught, and opens the finding from there", func() {
		stub := &stubAlerts{
			rules: []model.AlertRule{log4j},
			alerts: map[string][]model.Alert{"rule_1": {{
				ID: "rule_1:CVE-2021-44228", RuleID: "rule_1", RuleName: "Log4j",
				CVEID: "CVE-2021-44228", Reason: `matched "log4j"`, CreatedAt: time.Now(),
				Vulnerability: model.Vulnerability{CVEID: "CVE-2021-44228", Title: "Log4Shell",
					Scores: []model.CVSS{{BaseScore: 10, Severity: "CRITICAL"}}},
			}}},
		}
		m := press(alertsTab(stub), tea.KeyEnter)
		view := stripANSI(m.View())
		Expect(view).To(ContainSubstring(`Alerts  "Log4j"  ·  1`))
		Expect(view).To(ContainSubstring("CVE-2021-44228"))
		Expect(view).To(ContainSubstring("Log4Shell"))

		m = press(m, tea.KeyEnter)
		Expect(stripANSI(m.View())).To(ContainSubstring("▌ 2 Details"))
	})

	It("says plainly when a rule has caught nothing yet", func() {
		m := press(alertsTab(&stubAlerts{rules: []model.AlertRule{log4j}}), tea.KeyEnter)
		Expect(stripANSI(m.View())).To(ContainSubstring("nothing has matched yet"))
	})

	It("asks before removing a rule", func() {
		stub := &stubAlerts{rules: []model.AlertRule{log4j}}
		m := alertsTab(stub)
		m, _ = apply(m, key("d"))
		Expect(stripANSI(m.View())).To(ContainSubstring(`remove "Log4j" and the alerts it raised? y / n`))

		m, cmd := apply(m, key("y"))
		m = settle(m, cmd)
		Expect(stub.deleted).To(Equal([]string{"rule_1"}))
		Expect(stripANSI(m.View())).To(ContainSubstring("no alert rules yet"))
	})

	It("does not wrap a row at any width", func() {
		m := alertsTab(&stubAlerts{rules: []model.AlertRule{{ID: "r", Name: strings.Repeat("long name ", 8),
			Criteria: model.Criteria{Term: strings.Repeat("term ", 30)}}}})
		for _, width := range []int{60, 80, 120} {
			sized, _ := apply(m, tea.WindowSizeMsg{Width: width, Height: 40})
			for _, line := range viewLines(sized) {
				Expect(len([]rune(line))).To(BeNumerically("<=", width))
			}
		}
	})
})
