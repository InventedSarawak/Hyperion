// Package osvbulk is an OUTBOUND adapter implementing ports.Backfiller over
// OSV.dev's bulk exports: one zip per ecosystem holding every advisory OSV
// knows for it, one JSON file per record.
//
// It exists because the query API cannot answer "everything": OSV is queried
// by package, so history for a package nobody thought to name never arrives.
// The export has every package, and every record in it names the package it
// affects — which is the linkage blast radius needs and NVD never supplies.
// React2Shell (CVE-2025-55182, npm:react-server-dom-webpack) is exactly the
// kind of record that was missing.
//
// Docs: https://google.github.io/osv.dev/data/#data-dumps
package osvbulk

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/osv"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// DefaultBaseURL is the public bucket OSV publishes its exports to.
const DefaultBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

// DefaultEcosystems are the registries cortex models, spelled the way OSV
// names its export directories.
var DefaultEcosystems = []string{"npm", "PyPI", "Go", "Maven", "crates.io", "RubyGems", "NuGet", "Packagist"}

// batchSize is how many records are handed to emit at a time.
const batchSize = 500

// Client downloads and streams OSV ecosystem exports.
type Client struct {
	http       *http.Client
	baseURL    string
	ecosystems []string
	log        *slog.Logger
}

// New builds a bulk client. A nil httpClient gets one sized for the npm export
// (~200 MB); empty arguments fall back to the defaults.
func New(httpClient *http.Client, baseURL string, ecosystems []string) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Minute}
	}
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if len(ecosystems) == 0 {
		ecosystems = DefaultEcosystems
	}
	return &Client{http: httpClient, baseURL: strings.TrimRight(baseURL, "/"), ecosystems: ecosystems, log: slog.Default()}
}

// Kind reports the source this client speaks for: OSV is the package feed.
func (c *Client) Kind() valueobject.SourceKind { return valueobject.SourceKindPackageFeed }

// Backfill streams every record disclosed at or after `from`, ecosystem by
// ecosystem. One unreachable export is logged and skipped rather than failing
// the rest; an emit error stops everything, because it means the consumer has
// gone away.
func (c *Client) Backfill(ctx context.Context, from time.Time, emit func([]model.SourceSignal) error) error {
	var failed []string
	for _, ecosystem := range c.ecosystems {
		n, err := c.backfillEcosystem(ctx, ecosystem, from, emit)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if emitErr := (emitError{}); errors.As(err, &emitErr) {
				return emitErr.err
			}
			c.log.Error("osv export failed", "ecosystem", ecosystem, "error", err)
			failed = append(failed, ecosystem)
			continue
		}
		c.log.Info("osv export complete", "ecosystem", ecosystem, "records", n)
	}
	if len(failed) > 0 {
		return fmt.Errorf("osvbulk: exports failed: %s", strings.Join(failed, ", "))
	}
	return nil
}

// backfillEcosystem downloads one export to a temporary file and walks it.
// The archive is read from disk, not memory: zip needs random access to its
// central directory, and the npm export alone is hundreds of megabytes.
func (c *Client) backfillEcosystem(ctx context.Context, ecosystem string, from time.Time, emit func([]model.SourceSignal) error) (int, error) {
	path, err := c.download(ctx, ecosystem)
	if err != nil {
		return 0, err
	}
	defer os.Remove(path)

	archive, err := zip.OpenReader(path)
	if err != nil {
		return 0, fmt.Errorf("open %s export: %w", ecosystem, err)
	}
	defer archive.Close()

	var (
		batch   = make([]model.SourceSignal, 0, batchSize)
		emitted int
	)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := emit(batch); err != nil {
			return emitError{err}
		}
		emitted += len(batch)
		batch = make([]model.SourceSignal, 0, batchSize)
		return nil
	}

	for _, file := range archive.File {
		if err := ctx.Err(); err != nil {
			return emitted, err
		}
		if !strings.HasSuffix(file.Name, ".json") {
			continue
		}
		record, err := readRecord(file)
		if err != nil {
			c.log.Warn("skipping unreadable osv record", "ecosystem", ecosystem, "file", file.Name, "error", err)
			continue
		}
		if disclosed := osv.PublishedOrModified(record); !from.IsZero() && disclosed.Before(from) {
			continue
		}
		signal, ok := osv.ToSourceSignal(record, time.Time{})
		if !ok {
			continue
		}
		batch = append(batch, signal)
		if len(batch) == batchSize {
			if err := flush(); err != nil {
				return emitted, err
			}
		}
	}
	return emitted, flush()
}

// download fetches one ecosystem's export into a temporary file.
func (c *Client) download(ctx context.Context, ecosystem string) (string, error) {
	endpoint := fmt.Sprintf("%s/%s/all.zip", c.baseURL, url.PathEscape(ecosystem))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "hyperion-siphon/1.0")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("download %s export: %w", ecosystem, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s export: status %d", ecosystem, resp.StatusCode)
	}

	file, err := os.CreateTemp("", "osv-"+strings.ReplaceAll(ecosystem, "/", "_")+"-*.zip")
	if err != nil {
		return "", fmt.Errorf("temp file: %w", err)
	}
	if _, err := io.Copy(file, resp.Body); err != nil {
		file.Close()
		os.Remove(file.Name())
		return "", fmt.Errorf("download %s export: %w", ecosystem, err)
	}
	if err := file.Close(); err != nil {
		os.Remove(file.Name())
		return "", fmt.Errorf("temp file: %w", err)
	}
	return file.Name(), nil
}

func readRecord(file *zip.File) (osv.Vulnerability, error) {
	rc, err := file.Open()
	if err != nil {
		return osv.Vulnerability{}, err
	}
	defer rc.Close()

	var record osv.Vulnerability
	if err := json.NewDecoder(rc).Decode(&record); err != nil {
		return osv.Vulnerability{}, err
	}
	return record, nil
}

// emitError marks a failure of the consumer rather than of the export, so the
// walk stops instead of moving on to the next ecosystem.
type emitError struct{ err error }

func (e emitError) Error() string { return e.err.Error() }
func (e emitError) Unwrap() error { return e.err }
