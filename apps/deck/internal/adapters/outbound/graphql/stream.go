package graphql

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// streamPath is the gateway's live feed.
const streamPath = "/stream"

// StreamFindings subscribes to the gateway's Server-Sent Events feed.
//
// Through the gateway rather than straight to cortex, like every other call
// this adapter makes: the edge is where authentication, rate limiting and
// metering land in v4, and a client that streams around it skips all of them.
func (c *Client) StreamFindings(ctx context.Context) (<-chan model.Vulnerability, error) {
	url := strings.TrimSuffix(c.endpoint, "/graphql") + streamPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("stream: request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("stream: connect %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("stream: %s returned %s", url, resp.Status)
	}

	out := make(chan model.Vulnerability, streamBuffer)
	go func() {
		defer close(out)
		defer func() { _ = resp.Body.Close() }()
		readEvents(ctx, resp.Body, out)
	}()
	return out, nil
}

// streamBuffer holds a burst while the terminal is busy drawing.
const streamBuffer = 64

// sseFinding is the shape the gateway sends.
type sseFinding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Kind        string   `json:"kind"`
	Severity    string   `json:"severity"`
	Score       float64  `json:"score"`
	Sources     []string `json:"sources"`
	PublishedAt string   `json:"publishedAt"`
}

// readEvents parses the SSE stream until it ends or ctx is cancelled.
//
// SSE is line-oriented: "event:" names the type, "data:" carries the payload,
// a blank line ends the event, and a line starting with ":" is a comment —
// which is how the gateway sends its keep-alives.
func readEvents(ctx context.Context, body interface{ Read([]byte) (int, error) }, out chan<- model.Vulnerability) {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // a description can be long

	var event, data string
	for scanner.Scan() {
		if ctx.Err() != nil {
			return
		}
		line := scanner.Text()

		switch {
		case line == "":
			// Blank line: the event is complete.
			if event == "end" {
				return
			}
			if event == "finding" && data != "" {
				var f sseFinding
				if err := json.Unmarshal([]byte(data), &f); err == nil {
					select {
					case out <- f.toDomain():
					case <-ctx.Done():
						return
					}
				}
			}
			event, data = "", ""

		case strings.HasPrefix(line, ":"):
			// A keep-alive comment. Its only job is to have arrived.

		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))

		case strings.HasPrefix(line, "data:"):
			data = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		}
	}
}

func (f sseFinding) toDomain() model.Vulnerability {
	v := model.Vulnerability{
		CVEID:       f.ID,
		Title:       f.Title,
		Description: f.Description,
		Kind:        model.FindingKind(f.Kind),
		Sources:     f.Sources,
	}
	if f.Score > 0 || f.Severity != "" {
		v.Scores = []model.CVSS{{BaseScore: f.Score, Severity: f.Severity}}
	}
	if t, err := time.Parse(time.RFC3339, f.PublishedAt); err == nil {
		v.PublishedAt = t
	}
	return v
}
