// Package sourcehttp is the shared HTTP plumbing for siphon's source adapters:
// per-source rate limiting, bounded retry with exponential backoff, and JSON /
// raw body helpers. Each adapter supplies its own endpoints and mapping; none
// of them re-implement transport concerns.
package sourcehttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// maxRetries bounds the backoff loop for throttled/transient responses.
const maxRetries = 4

// Client is a polite HTTP client: it paces requests and retries throttling.
type Client struct {
	http    *http.Client
	limiter *rate.Limiter
	headers map[string]string
	agent   string
}

// Option customizes a Client.
type Option func(*Client)

// WithHeader adds a header sent on every request (e.g. an auth token).
func WithHeader(key, value string) Option {
	return func(c *Client) {
		if key != "" && value != "" {
			c.headers[key] = value
		}
	}
}

// WithTimeout overrides the per-request timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.http.Timeout = d
		}
	}
}

// WithHTTPClient injects a client (used by tests to target httptest servers).
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) {
		if h != nil {
			timeout := c.http.Timeout
			c.http = h
			if c.http.Timeout == 0 {
				c.http.Timeout = timeout
			}
		}
	}
}

// New builds a client pacing requests at one per `delay`.
func New(delay time.Duration, opts ...Option) *Client {
	if delay <= 0 {
		delay = time.Second
	}
	c := &Client{
		http:    &http.Client{Timeout: 60 * time.Second},
		limiter: rate.NewLimiter(rate.Every(delay), 1),
		headers: map[string]string{},
		agent:   "hyperion-siphon/1.0",
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// GetJSON fetches a URL and decodes the JSON body into out.
func (c *Client) GetJSON(ctx context.Context, url string, out any) error {
	body, err := c.GetBytes(ctx, url)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode json from %s: %w", url, err)
	}
	return nil
}

// GetBytes fetches a URL and returns the raw body, retrying throttled and
// transient responses.
func (c *Client) GetBytes(ctx context.Context, url string) ([]byte, error) {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter: %w", err)
		}

		body, retryable, err := c.once(ctx, url)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if !retryable || attempt == maxRetries {
			break
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(1<<attempt) * 2 * time.Second):
		}
	}
	return nil, lastErr
}

// once performs a single request; the bool reports whether a retry may help.
func (c *Client) once(ctx context.Context, url string) ([]byte, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, fmt.Errorf("new request %s: %w", url, err)
	}
	req.Header.Set("User-Agent", c.agent)
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		// Network/timeout errors are worth retrying; a cancelled context is not.
		return nil, !errors.Is(err, context.Canceled), fmt.Errorf("get %s: %w", url, err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusOK:
	case quotaExhausted(resp):
		// The request budget is spent: retrying cannot succeed before the reset,
		// and each retry would also burn the limiter delay, stalling the whole
		// poll. Fail fast so the other sources still get their turn.
		return nil, false, fmt.Errorf("rate limit exhausted for %s (resets %s); supply a token to raise it",
			url, resetHint(resp))
	case resp.StatusCode == http.StatusForbidden,
		resp.StatusCode == http.StatusTooManyRequests,
		resp.StatusCode >= 500:
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, true, fmt.Errorf("throttled/transient %d from %s: %s", resp.StatusCode, url, strings.TrimSpace(string(snippet)))
	default:
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, false, fmt.Errorf("unexpected status %d from %s: %s", resp.StatusCode, url, strings.TrimSpace(string(snippet)))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, true, fmt.Errorf("read body from %s: %w", url, err)
	}
	return body, false, nil
}

// quotaExhausted reports whether the response says the caller's request budget
// is spent (GitHub and similar APIs advertise this via X-RateLimit-Remaining).
func quotaExhausted(resp *http.Response) bool {
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusTooManyRequests {
		return false
	}
	return resp.Header.Get("X-RateLimit-Remaining") == "0"
}

// resetHint renders the rate-limit reset time for the error message.
func resetHint(resp *http.Response) string {
	raw := resp.Header.Get("X-RateLimit-Reset")
	if raw == "" {
		return "unknown"
	}
	epoch, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return raw
	}
	return time.Unix(epoch, 0).UTC().Format(time.RFC3339)
}
