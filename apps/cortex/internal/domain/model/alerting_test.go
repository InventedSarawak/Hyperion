package model_test

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

func vuln(cve, title string, severity model.Severity, packages ...valueobject.PackageRef) model.Vulnerability {
	v := model.Vulnerability{CVEID: cve, Title: title, AffectedPackages: packages}
	if severity != model.SeverityUnknown {
		v.Scores = []model.CVSS{{Severity: severity}}
	}
	return v
}

var _ = Describe("Severity ordering", func() {
	It("ranks the scale", func() {
		Expect(model.SeverityCritical.AtLeast(model.SeverityHigh)).To(BeTrue())
		Expect(model.SeverityHigh.AtLeast(model.SeverityHigh)).To(BeTrue())
		Expect(model.SeverityLow.AtLeast(model.SeverityHigh)).To(BeFalse())
	})

	It("never treats an unscored finding as clearing a threshold", func() {
		// "We don't know" must not be promoted to "bad enough to wake you".
		Expect(model.SeverityUnknown.AtLeast(model.SeverityLow)).To(BeFalse())
		Expect(model.SeverityUnknown.IsRanked()).To(BeFalse())
	})

	It("reports the worst rating when feeds disagree", func() {
		v := model.Vulnerability{Scores: []model.CVSS{
			{Severity: model.SeverityLow},
			{Severity: model.SeverityCritical},
			{Severity: model.SeverityMedium},
		}}
		Expect(v.TopSeverity()).To(Equal(model.SeverityCritical))
	})

	It("reports unknown when nothing was scored", func() {
		Expect(model.Vulnerability{}.TopSeverity()).To(Equal(model.SeverityUnknown))
	})
})

var _ = Describe("AlertRule", func() {
	lodash := valueobject.NewPackageRef("npm", "lodash", "")
	next := valueobject.NewPackageRef("npm", "next", "")

	It("rejects a rule that states no condition", func() {
		// A rule matching everything is the alert fatigue this exists to stop.
		Expect(model.AlertRule{}.Validate()).To(MatchError(model.ErrEmptyAlertRule))
		Expect(model.AlertRule{Term: "log4j"}.Validate()).To(Succeed())
	})

	It("matches free text across id, title and description", func() {
		rule := model.AlertRule{Term: "log4j"}
		Expect(rule.Matches(vuln("CVE-2021-44228", "Log4Shell in Log4j", model.SeverityCritical))).To(BeTrue())
		Expect(rule.Matches(model.Vulnerability{CVEID: "CVE-1", Description: "affects log4j core"})).To(BeTrue())
		Expect(rule.Matches(vuln("CVE-2", "unrelated", model.SeverityHigh))).To(BeFalse())
	})

	It("matches a minimum severity, inclusive", func() {
		rule := model.AlertRule{MinSeverity: model.SeverityHigh}
		Expect(rule.Matches(vuln("CVE-1", "x", model.SeverityCritical))).To(BeTrue())
		Expect(rule.Matches(vuln("CVE-2", "x", model.SeverityHigh))).To(BeTrue())
		Expect(rule.Matches(vuln("CVE-3", "x", model.SeverityMedium))).To(BeFalse())
		Expect(rule.Matches(vuln("CVE-4", "x", model.SeverityUnknown))).To(BeFalse())
	})

	It("matches a watched library regardless of version", func() {
		rule := model.AlertRule{Packages: []valueobject.PackageRef{lodash}}
		pinned := valueobject.NewPackageRef("npm", "lodash", "< 4.17.21")

		Expect(rule.Matches(vuln("CVE-1", "x", model.SeverityHigh, pinned))).To(BeTrue())
		Expect(rule.Matches(vuln("CVE-2", "x", model.SeverityHigh, next))).To(BeFalse())
	})

	It("does not confuse the same name in different ecosystems", func() {
		rule := model.AlertRule{Packages: []valueobject.PackageRef{
			valueobject.NewPackageRef("pypi", "requests", ""),
		}}
		gem := valueobject.NewPackageRef("rubygems", "requests", "")
		Expect(rule.Matches(vuln("CVE-1", "x", model.SeverityHigh, gem))).To(BeFalse())
	})

	It("matches an ecosystem", func() {
		rule := model.AlertRule{Ecosystems: []valueobject.Ecosystem{valueobject.EcosystemNPM}}
		Expect(rule.Matches(vuln("CVE-1", "x", model.SeverityHigh, lodash))).To(BeTrue())
		Expect(rule.Matches(vuln("CVE-2", "x", model.SeverityHigh,
			valueobject.NewPackageRef("go", "golang.org/x/net", "")))).To(BeFalse())
	})

	It("ANDs its conditions, so each one narrows the match", func() {
		rule := model.AlertRule{Term: "prototype", MinSeverity: model.SeverityHigh,
			Packages: []valueobject.PackageRef{lodash}}

		Expect(rule.Matches(vuln("CVE-1", "prototype pollution", model.SeverityHigh, lodash))).To(BeTrue())
		Expect(rule.Matches(vuln("CVE-2", "prototype pollution", model.SeverityLow, lodash))).To(BeFalse())
		Expect(rule.Matches(vuln("CVE-3", "prototype pollution", model.SeverityHigh, next))).To(BeFalse())
		Expect(rule.Matches(vuln("CVE-4", "something else", model.SeverityHigh, lodash))).To(BeFalse())
	})

	It("explains what matched", func() {
		rule := model.AlertRule{Term: "prototype", MinSeverity: model.SeverityHigh,
			Packages: []valueobject.PackageRef{lodash}}
		reason := rule.Reason(vuln("CVE-1", "prototype pollution", model.SeverityHigh, lodash))

		Expect(reason).To(ContainSubstring(`matched "prototype"`))
		Expect(reason).To(ContainSubstring("severity >= high"))
		Expect(reason).To(ContainSubstring("npm:lodash"))
	})
})

var _ = Describe("Subscription", func() {
	valid := model.AlertRule{Term: "log4j"}

	It("requires a name, because the name is what a subscriber sees", func() {
		Expect(model.Subscription{Rule: valid}.Validate()).To(MatchError(model.ErrMissingSubscriptionName))
		Expect(model.Subscription{Name: "Log4j watch", Rule: valid}.Validate()).To(Succeed())
	})

	It("rejects an empty rule through the subscription too", func() {
		Expect(model.Subscription{Name: "everything"}.Validate()).To(MatchError(model.ErrEmptyAlertRule))
	})

	It("fills in tenant and creation time", func() {
		now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
		got := model.Subscription{Name: "  Log4j watch  ", Rule: valid}.WithDefaults(now)

		Expect(got.Tenant).To(Equal(model.DefaultTenant))
		Expect(got.CreatedAt).To(Equal(now))
		Expect(got.Name).To(Equal("Log4j watch"))
	})
})

var _ = Describe("Alert", func() {
	sub := model.Subscription{ID: "sub-1", Tenant: "acme", Name: "Log4j watch",
		Rule: model.AlertRule{Term: "log4j"}}

	It("is identified by subscription and CVE, so a re-observation updates it", func() {
		now := time.Now()
		first := model.NewAlert(sub, vuln("CVE-2021-44228", "Log4Shell", model.SeverityCritical), now)
		again := model.NewAlert(sub, vuln("CVE-2021-44228", "Log4Shell (revised)", model.SeverityCritical), now.Add(time.Hour))

		Expect(first.ID).To(Equal(again.ID))
		Expect(first.ID).To(Equal("sub-1:CVE-2021-44228"))
	})

	It("carries the CVE id rather than a frozen copy of the record", func() {
		alert := model.NewAlert(sub, vuln("CVE-2021-44228", "Log4Shell", model.SeverityCritical), time.Now())

		Expect(alert.CVEID).To(Equal("CVE-2021-44228"))
		Expect(alert.Tenant).To(Equal("acme"))
		Expect(alert.Reason).To(ContainSubstring("log4j"))
	})

	It("requires enough identity to be actionable", func() {
		Expect(model.Alert{}.Validate()).To(MatchError(model.ErrIncompleteAlert))
		Expect(model.Alert{SubscriptionID: "s", CVEID: "CVE-1"}.Validate()).To(Succeed())
	})

	It("keys deduplication on the pair, not on time", func() {
		alert := model.NewAlert(sub, vuln("CVE-1", "x", model.SeverityHigh), time.Now())
		Expect(alert.DedupeKey()).To(Equal("alert:sub-1:CVE-1"))
	})
})
