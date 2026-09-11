// Package config loads deck's settings through Hyperion's centralized,
// namespaced config system. Every key is deck.<NAME> -> DECK_<NAME>.
package config

import (
	"time"

	"github.com/inventedsarawak/hyperion/packages/common/config"
)

// Service is the config namespace for this microservice.
const Service = "deck"

// Defaults for a local development stack.
const (
	DefaultCortexGRPCAddr = "localhost:50051"
	DefaultGatewayURL     = "http://localhost:8080/graphql"
	// TransportGateway routes through nexus, so deck inherits whatever the
	// edge enforces. TransportGRPC talks to cortex directly and is for
	// debugging a cortex the gateway cannot reach.
	TransportGateway = "gateway"
	TransportGRPC    = "grpc"
	// No query is the live feed: the newest findings first. It used to
	// default to "cve", which matched every record equally and ranked them by
	// an accidental text score — the oddest-looking order possible.
	DefaultFeedQuery = ""
)

// Config holds deck's runtime settings.
type Config struct {
	Transport           string
	GatewayURL          string
	CortexGRPCAddr      string
	FeedQuery           string
	RefreshInterval     time.Duration
	PageSize            int
	BlastRadiusMaxDepth int

	loader *config.Loader
}

// Load reads configuration from the environment, applying defaults.
func Load() Config {
	l := config.For(Service)
	return Config{
		loader:              l,
		Transport:           l.String("TRANSPORT", TransportGateway),
		GatewayURL:          l.String("GATEWAY_URL", DefaultGatewayURL),
		CortexGRPCAddr:      l.String("CORTEX_GRPC_ADDR", DefaultCortexGRPCAddr),
		FeedQuery:           l.String("FEED_QUERY", DefaultFeedQuery),
		RefreshInterval:     l.Duration("REFRESH_INTERVAL", 30*time.Second),
		PageSize:            l.Int("PAGE_SIZE", 25),
		BlastRadiusMaxDepth: l.Int("BLAST_RADIUS_MAX_DEPTH", 3),
	}
}

// Describe returns every resolved setting with secrets masked.
func (c Config) Describe() []config.Entry {
	if c.loader == nil {
		return nil
	}
	return c.loader.Describe()
}

// Endpoint describes where deck will connect, for display in the UI.
func (c Config) Endpoint() string {
	if c.Transport == TransportGRPC {
		return "cortex " + c.CortexGRPCAddr
	}
	return "nexus " + c.GatewayURL
}
