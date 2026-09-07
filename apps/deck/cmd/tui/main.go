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
	grpcadapter "github.com/inventedsarawak/hyperion/apps/deck/internal/adapters/outbound/grpc"
	"github.com/inventedsarawak/hyperion/apps/deck/internal/application/commands"
	"github.com/inventedsarawak/hyperion/apps/deck/internal/application/queries"
	"github.com/inventedsarawak/hyperion/apps/deck/internal/platform/config"
)

func main() {
	// The TUI owns stdout, so logs go to stderr and stay out of the frame.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	cfg := config.Load()

	client, err := grpcadapter.Dial(cfg.CortexGRPCAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "deck: cannot reach the intelligence service at %s: %v\n",
			cfg.CortexGRPCAddr, err)
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
			CortexAddr:      cfg.CortexGRPCAddr,
		},
	)

	if _, err := tea.NewProgram(m, tea.WithAltScreen()).Run(); err != nil {
		fmt.Fprintf(os.Stderr, "deck: %v\n", err)
		os.Exit(1)
	}
}
