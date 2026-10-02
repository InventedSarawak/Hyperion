package commands_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/application/commands"
	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

type fakeAlerting struct {
	created  model.Criteria
	name     string
	createdN int
}

func (f *fakeAlerting) AlertRules(context.Context) ([]model.AlertRule, error) { return nil, nil }
func (f *fakeAlerting) CreateAlertRule(_ context.Context, name string, c model.Criteria) (model.AlertRule, error) {
	f.createdN++
	f.name, f.created = name, c
	return model.AlertRule{ID: "rule_1", Name: name, Criteria: c}, nil
}
func (f *fakeAlerting) DeleteAlertRule(context.Context, string) error { return nil }
func (f *fakeAlerting) Alerts(context.Context, string, int) ([]model.Alert, error) {
	return nil, nil
}

var _ = Describe("ManageAlertRules", func() {
	ctx := context.Background()

	It("tidies a rule before sending it", func() {
		api := &fakeAlerting{}
		_, err := commands.NewManageAlertRules(api).Create(ctx, "  Log4j  ", model.Criteria{Term: " log4j ", MinSeverity: "high"})
		Expect(err).ToNot(HaveOccurred())
		Expect(api.name).To(Equal("Log4j"))
		Expect(api.created.Term).To(Equal("log4j"))
		Expect(api.created.MinSeverity).To(Equal("HIGH"))
	})

	It("refuses a rule with no name, without asking the gateway", func() {
		api := &fakeAlerting{}
		_, err := commands.NewManageAlertRules(api).Create(ctx, " ", model.Criteria{Term: "log4j"})
		Expect(err).To(MatchError(ContainSubstring("give it a name")))
		Expect(api.createdN).To(BeZero())
	})

	It("refuses a rule that would match every finding", func() {
		// No term, any severity: that is every finding ever ingested, which
		// is the alert fatigue the platform exists to prevent.
		api := &fakeAlerting{}
		_, err := commands.NewManageAlertRules(api).Create(ctx, "Everything", model.Criteria{Term: "  "})
		Expect(err).To(MatchError(ContainSubstring("match every finding")))
		Expect(api.createdN).To(BeZero())
	})

	It("accepts a rule about severity alone", func() {
		api := &fakeAlerting{}
		_, err := commands.NewManageAlertRules(api).Create(ctx, "Criticals", model.Criteria{MinSeverity: "CRITICAL"})
		Expect(err).ToNot(HaveOccurred())
	})

	It("says so when it is not connected", func() {
		_, err := commands.NewManageAlertRules(nil).Rules(ctx)
		Expect(err).To(MatchError(ContainSubstring("not connected")))
	})
})
