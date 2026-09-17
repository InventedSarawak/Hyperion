// Package kafka wraps the Kafka client every Hyperion service shares, so that
// "how we talk to the broker" is decided once rather than per service.
//
// It deliberately knows nothing about vulnerabilities, repositories or any
// other domain type: it carries protobuf messages, and the caller says which
// message and which key. A service's adapter is what maps its domain onto a
// contract type; this package is the transport underneath that mapping.
//
// Reference: https://pkg.go.dev/github.com/twmb/franz-go/pkg/kgo
package kafka

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

// TopicSignals carries hyperion.events.v1.SignalDiscovered — one record per
// finding reported by a source. Versioned like the protos it carries: a
// breaking payload change gets a .v2 topic beside this one, so old and new
// consumers can run at the same time instead of one migration cutting over.
const TopicSignals = "hyperion.signals.v1"

// TopicDependencies carries hyperion.events.v1.DependencyObserved — one record
// per read of one repository's manifests. Separate from the signal topic
// because the two have nothing to do with each other operationally: a backlog
// of advisories should not delay the supply-chain graph, and a consumer of one
// has no use for the other.
const TopicDependencies = "hyperion.dependencies.v1"

// DefaultBroker is where the local docker-compose broker listens.
const DefaultBroker = "localhost:9092"

// ErrNoBrokers means the caller asked for a client without saying where the
// cluster is. Failing here beats a client that retries a nonexistent broker
// forever while the service looks healthy.
var ErrNoBrokers = errors.New("kafka: no brokers configured")

// Config is the part of the connection every client needs, whatever it does
// with the connection afterwards.
type Config struct {
	// Brokers is the seed list. One entry is enough — the client discovers
	// the rest of the cluster from it.
	Brokers []string

	// ClientID names this process in the broker's logs and metrics. Worth
	// setting: "which consumer is lagging" is otherwise a guessing game.
	ClientID string

	// DialTimeout bounds a single connection attempt. Zero takes the default.
	DialTimeout time.Duration
}

func (c Config) validate() error {
	if len(c.Brokers) == 0 {
		return ErrNoBrokers
	}
	for _, b := range c.Brokers {
		if strings.TrimSpace(b) == "" {
			return fmt.Errorf("kafka: empty broker address in %q", c.Brokers)
		}
	}
	return nil
}

// baseOptions are the client options shared by producers and consumers.
func (c Config) baseOptions() []kgo.Opt {
	opts := []kgo.Opt{kgo.SeedBrokers(c.Brokers...)}
	if c.ClientID != "" {
		opts = append(opts, kgo.ClientID(c.ClientID))
	}
	if c.DialTimeout > 0 {
		opts = append(opts, kgo.DialTimeout(c.DialTimeout))
	}
	return opts
}

// ParseBrokers splits a comma-separated broker list, trimming blanks. It is
// here rather than in each service's config so that SIPHON_KAFKA_BROKERS and
// CORTEX_KAFKA_BROKERS cannot drift in how they are read.
func ParseBrokers(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
