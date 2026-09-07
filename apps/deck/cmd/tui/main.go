// Command tui is deck's entrypoint: the composition root that wires the gRPC
// client into the use cases and runs the Bubble Tea program.
//
// deck talks to cortex directly rather than through the nexus gateway: it is
// an operator's console on the internal network, and GraphQL would add a hop
// without adding anything a terminal client needs.
package main

import (
	"fmt"
	"log/slog"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/adapters/inbound/tui"
	graphqladapter "github.com/inventedsarawak/hyperion/apps/deck/internal/adapters/outbound/graphql"
	grpcadapter "github.com/inventedsarawak/hyperion/apps/deck/internal/adapters/outbound/grpc"
	"github.com/inventedsarawak/hyperion/apps/deck/internal/application/commands"
	"github.com/inventedsarawak/hyperion/apps/deck/internal/application/queries"
	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/ports"
	"github.com/inventedsarawak/hyperion/apps/deck/internal/platform/config"
)

func main() {
	// The TUI owns stdout, so logs go to stderr and stay out of the frame.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	cfg := config.Load()

	client, err := dial(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "deck: cannot reach %s: %v\n", cfg.Endpoint(), err)
		os.Exit(1)
	}
	defer client.Close()

	// Compose the hexagon: outbound adapter -> use cases -> inbound adapter.
	m := tui.New(
		commands.NewRunSearch(client),
		queries.NewGetBlastRadius(client),
		tui.Options{
			Query:           cfg.FeedQuery,
			PageSize:        cfg.PageSize,
			MaxDepth:        cfg.BlastRadiusMaxDepth,
			RefreshInterval: cfg.RefreshInterval,
			Endpoint:        cfg.Endpoint(),
		},
	)

	if _, err := tea.NewProgram(m, tea.WithAltScreen()).Run(); err != nil {
		fmt.Fprintf(os.Stderr, "deck: %v\n", err)
		os.Exit(1)
	}
}

// intelligenceAPI is what both transports satisfy: the outbound port plus a
// Close, so the composition root can treat them alike.
type intelligenceAPI interface {
	ports.IntelligenceAPI
	Close() error
}

// dial picks the transport. The gateway is the default: routing through nexus
// means deck is subject to the same edge policy as every other client, rather
// than quietly bypassing it.
func dial(cfg config.Config) (intelligenceAPI, error) {
	if cfg.Transport == config.TransportGRPC {
		return grpcadapter.Dial(cfg.CortexGRPCAddr)
	}
	return graphqladapter.New(cfg.GatewayURL, nil), nil
}
