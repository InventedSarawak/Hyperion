package grpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	intelv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/intelligence/v1"

	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/model"
)

// streamBuffer lets the gateway hold a short burst while a viewer's connection
// is written to. It is small on purpose: the gateway is a relay, and a backlog
// here would only delay the same records it cannot make the viewer read faster.
const streamBuffer = 64

// StreamFindings opens cortex's live feed and relays it as domain values.
//
// No timeout is applied, unlike every other call on this client: the others
// are questions, and this one is a subscription that is supposed to stay open
// until the caller goes away.
func (c *Client) StreamFindings(ctx context.Context, kinds []model.FindingKind) (<-chan model.Vulnerability, error) {
	stream, err := c.stub.StreamFindings(ctx, &intelv1.StreamFindingsRequest{Kinds: wireKinds(kinds)})
	if err != nil {
		return nil, fmt.Errorf("grpc: stream findings: %w", err)
	}

	out := make(chan model.Vulnerability, streamBuffer)
	go func() {
		// Closing is how the reader learns the feed ended, whether that was a
		// clean shutdown, a dropped connection, or cortex restarting.
		defer close(out)

		for {
			msg, err := stream.Recv()
			switch {
			case errors.Is(err, io.EOF), errors.Is(err, context.Canceled):
				return
			case err != nil:
				if ctx.Err() == nil {
					slog.Default().Warn("live findings stream ended", "error", err)
				}
				return
			}

			select {
			case out <- toViewModel(msg.GetVulnerability()):
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}
