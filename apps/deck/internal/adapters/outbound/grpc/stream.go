package grpc

import (
	"context"
	"errors"
	"fmt"
	"io"

	intelv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/intelligence/v1"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// streamBuffer holds a burst while the terminal is busy drawing.
const streamBuffer = 64

// StreamFindings subscribes to cortex's live feed directly.
//
// This is the DECK_TRANSPORT=grpc path, which exists for debugging a cortex
// the gateway cannot reach. The gateway path is the default, and the one that
// will carry authentication.
func (c *Client) StreamFindings(ctx context.Context) (<-chan model.Vulnerability, error) {
	stream, err := c.stub.StreamFindings(ctx, &intelv1.StreamFindingsRequest{})
	if err != nil {
		return nil, fmt.Errorf("grpc: stream findings: %w", err)
	}

	out := make(chan model.Vulnerability, streamBuffer)
	go func() {
		defer close(out)
		for {
			msg, err := stream.Recv()
			if err != nil {
				// EOF, a cancelled context or a dropped connection all mean
				// the same thing to a reader: the feed has ended.
				if !errors.Is(err, io.EOF) && ctx.Err() == nil {
					_ = err
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
