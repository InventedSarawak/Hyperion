package graphql_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	gatewayadapter "github.com/inventedsarawak/hyperion/apps/deck/internal/adapters/outbound/graphql"
	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

var _ = Describe("Gateway client alerting", func() {
	ctx := context.Background()

	It("lists alert rules with their criteria", func() {
		srv := gateway(`{"data":{"alertRules":[{"id":"rule_1","tenant":"default","name":"Log4j",
		  "createdAt":"2026-10-01T10:00:00Z",
		  "criteria":{"term":"log4j","minSeverity":"HIGH","packages":["maven:log4j-core"],"ecosystems":[]}}]}}`, 0, nil)
		defer srv.Close()

		rules, err := gatewayadapter.New(srv.URL, srv.Client()).AlertRules(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(rules).To(HaveLen(1))
		Expect(rules[0].Name).To(Equal("Log4j"))
		Expect(rules[0].Criteria.Summary()).To(Equal(`"log4j" · high+ · maven:log4j-core`))
		Expect(rules[0].CreatedAt.Year()).To(Equal(2026))
	})

	It("leaves an unchosen severity out of a new rule rather than sending it empty", func() {
		var req map[string]any
		srv := gateway(`{"data":{"createAlertRule":{"id":"rule_2","name":"Next","criteria":{"term":"next"}}}}`, 0, &req)
		defer srv.Close()

		rule, err := gatewayadapter.New(srv.URL, srv.Client()).
			CreateAlertRule(ctx, "Next", model.Criteria{Term: "next"})
		Expect(err).ToNot(HaveOccurred())
		Expect(rule.ID).To(Equal("rule_2"))

		vars := req["variables"].(map[string]any)
		Expect(vars["name"]).To(Equal("Next"))
		criteria := vars["criteria"].(map[string]any)
		Expect(criteria).To(HaveKeyWithValue("term", "next"))
		Expect(criteria).ToNot(HaveKey("minSeverity"))
	})

	It("passes the gateway's refusal through as it is worded", func() {
		srv := gateway(`{"data":null,"errors":[{"message":"a rule needs at least one condition"}]}`, 0, nil)
		defer srv.Close()

		_, err := gatewayadapter.New(srv.URL, srv.Client()).CreateAlertRule(ctx, "x", model.Criteria{})
		Expect(err).To(MatchError("a rule needs at least one condition"))
	})

	It("reads alerts with the finding they matched", func() {
		var req map[string]any
		srv := gateway(`{"data":{"alerts":[{"id":"rule_1:CVE-2021-44228","ruleId":"rule_1","ruleName":"Log4j",
		  "cveId":"CVE-2021-44228","reason":"matched \"log4j\"","createdAt":"2026-10-01T10:00:00Z",
		  "vulnerability":{"cveId":"CVE-2021-44228","title":"Log4Shell",
		    "scores":[{"baseScore":10,"severity":"CRITICAL"}]}}]}}`, 0, &req)
		defer srv.Close()

		alerts, err := gatewayadapter.New(srv.URL, srv.Client()).Alerts(ctx, "rule_1", 50)
		Expect(err).ToNot(HaveOccurred())
		Expect(alerts).To(HaveLen(1))
		Expect(alerts[0].RuleName).To(Equal("Log4j"))
		Expect(alerts[0].Vulnerability.SeverityLabel()).To(Equal("CRITICAL"))
		Expect(req["variables"]).To(HaveKeyWithValue("ruleId", "rule_1"))
	})

	It("still names the finding when the record behind an alert is gone", func() {
		// A finding can be purged as withdrawn after it alerted. The alert
		// still says which one it was.
		srv := gateway(`{"data":{"alerts":[{"id":"a","ruleId":"r","cveId":"CVE-2020-1","vulnerability":null}]}}`, 0, nil)
		defer srv.Close()

		alerts, err := gatewayadapter.New(srv.URL, srv.Client()).Alerts(ctx, "", 50)
		Expect(err).ToNot(HaveOccurred())
		Expect(alerts[0].Vulnerability.CVEID).To(Equal("CVE-2020-1"))
	})
})
