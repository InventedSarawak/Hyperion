// Package health reports whether a service can do its job.
//
// A bound port is not health. scripts/system.sh used to probe cortex by
// opening a TCP connection to :50051, which proves the listener exists and
// nothing else — a cortex whose Postgres had gone would answer that probe all
// day while failing every request. A container orchestrator makes the same
// mistake more expensively: it restarts on a failed liveness probe and routes
// traffic on a passing readiness one.
//
// So a check names a dependency and asks it a question. What the answers mean
// is the service's business, which is why a check says whether it is
// Required: cortex cannot serve a finding without Postgres, but it is
// deliberately designed to keep ingesting while Elasticsearch is down, and a
// probe that failed on that would turn a degraded service into an outage.
package health

import (
	"context"
	"sync"
	"time"
)

// Probe asks one dependency whether it is reachable.
type Probe func(ctx context.Context) error

// Check is one named dependency and how to ask it.
type Check struct {
	Name  string
	Probe Probe
	// Required says the service cannot do its job without this one. A
	// failing required check makes the service unhealthy; a failing optional
	// one is reported and nothing more.
	Required bool
}

// Status is one dependency's last answer.
type Status struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
}

// Report is what every dependency answered, and the verdict.
type Report struct {
	// Healthy is false when any required check failed. It is what a
	// readiness probe should act on.
	Healthy bool      `json:"healthy"`
	Checks  []Status  `json:"checks"`
	At      time.Time `json:"at"`
}

// Degraded reports whether an optional dependency is failing while the
// service is still healthy — worth saying out loud, not worth acting on.
func (r Report) Degraded() bool {
	for _, c := range r.Checks {
		if !c.OK && !c.Required {
			return true
		}
	}
	return false
}

// Failing names the checks that did not answer, required first.
func (r Report) Failing() []string {
	var required, optional []string
	for _, c := range r.Checks {
		if c.OK {
			continue
		}
		if c.Required {
			required = append(required, c.Name)
		} else {
			optional = append(optional, c.Name)
		}
	}
	return append(required, optional...)
}

// Checker runs a set of checks, with a timeout per probe.
type Checker struct {
	checks  []Check
	timeout time.Duration
}

// New builds a checker. A probe that has not answered within timeout counts as
// failed: a dependency too slow to answer is one the service cannot use, and a
// health endpoint that blocks is worse than one that says no.
func New(timeout time.Duration, checks ...Check) *Checker {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &Checker{checks: checks, timeout: timeout}
}

// Run asks every dependency, in parallel, and returns what they said.
func (c *Checker) Run(ctx context.Context) Report {
	report := Report{Healthy: true, At: time.Now().UTC(), Checks: make([]Status, len(c.checks))}
	if len(c.checks) == 0 {
		return report
	}

	var wg sync.WaitGroup
	for i, check := range c.checks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			probeCtx, cancel := context.WithTimeout(ctx, c.timeout)
			defer cancel()

			status := Status{Name: check.Name, Required: check.Required, OK: true}
			if err := check.Probe(probeCtx); err != nil {
				status.OK, status.Error = false, err.Error()
			}
			report.Checks[i] = status
		}()
	}
	wg.Wait()

	for _, status := range report.Checks {
		if !status.OK && status.Required {
			report.Healthy = false
		}
	}
	return report
}
