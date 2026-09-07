// Package androzoo is a thin client over the AndroZoo HTTP API
// (https://androzoo.uni.lu/api_doc).
//
// The API exposes two things only: APK retrieval by SHA-256 and Google Play
// metadata by package name. There is no search endpoint — selecting samples on
// package name, date, size or VT count is done against the latest.csv index,
// which lives elsewhere in this module.
package androzoo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const DefaultBaseURL = "https://androzoo.uni.lu"

// MaxConcurrentDownloads is the ceiling AndroZoo asks callers to respect.
const MaxConcurrentDownloads = 20

var sha256Re = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

type Client struct {
	key     string
	baseURL string
	http    *http.Client
}

type Option func(*Client)

func WithBaseURL(u string) Option {
	return func(c *Client) { c.baseURL = strings.TrimRight(u, "/") }
}

func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

func New(key string, opts ...Option) *Client {
	c := &Client{
		key:     key,
		baseURL: DefaultBaseURL,
		// No overall timeout: an APK can be hundreds of megabytes.
		http: &http.Client{
			Transport: &http.Transport{
				ResponseHeaderTimeout: 60 * time.Second,
				MaxIdleConnsPerHost:   MaxConcurrentDownloads,
			},
		},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// APIError carries the status of a rejected request. AndroZoo answers with
// plain text, so the body is kept as-is.
type APIError struct {
	StatusCode int
	Endpoint   string
	Body       string
}

func (e *APIError) Error() string {
	switch e.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Sprintf("androzoo %s: rejected (%d) — check the API key and that it is approved for downloads", e.Endpoint, e.StatusCode)
	case http.StatusNotFound:
		return fmt.Sprintf("androzoo %s: not found (404)", e.Endpoint)
	}
	body := strings.TrimSpace(e.Body)
	if len(body) > 200 {
		body = body[:200]
	}
	return fmt.Sprintf("androzoo %s: HTTP %d: %s", e.Endpoint, e.StatusCode, body)
}

func (c *Client) do(ctx context.Context, path string, q url.Values, endpoint string) (*http.Response, error) {
	if c.key == "" {
		return nil, fmt.Errorf("androzoo %s: no API key", endpoint)
	}
	if q == nil {
		q = url.Values{}
	}
	q.Set("apikey", c.key)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("androzoo %s: %w", endpoint, err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, &APIError{StatusCode: resp.StatusCode, Endpoint: endpoint, Body: string(body)}
	}
	return resp, nil
}

// Download streams the APK identified by sha into w and returns the number of
// bytes written. The caller keeps ownership of w.
func (c *Client) Download(ctx context.Context, sha string, w io.Writer) (int64, error) {
	sha = strings.TrimSpace(sha)
	if !sha256Re.MatchString(sha) {
		return 0, fmt.Errorf("androzoo download: %q is not a SHA-256", sha)
	}
	resp, err := c.do(ctx, "/api/download", url.Values{"sha256": {sha}}, "download")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return io.Copy(w, resp.Body)
}

// GPMetadata returns every Google Play metadata record AndroZoo holds for a
// package, newest first as returned by the API.
func (c *Client) GPMetadata(ctx context.Context, pkg string) ([]json.RawMessage, error) {
	pkg = strings.TrimSpace(pkg)
	if pkg == "" {
		return nil, fmt.Errorf("androzoo gp_metadata: empty package name")
	}
	resp, err := c.do(ctx, "/api/get_gp_metadata/"+url.PathEscape(pkg), nil, "get_gp_metadata")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var records []json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		return nil, fmt.Errorf("androzoo gp_metadata: decoding %s: %w", pkg, err)
	}
	return records, nil
}

// GPMetadataVersion returns the metadata record for one version code.
func (c *Client) GPMetadataVersion(ctx context.Context, pkg string, versionCode int64) (json.RawMessage, error) {
	pkg = strings.TrimSpace(pkg)
	if pkg == "" {
		return nil, fmt.Errorf("androzoo gp_metadata: empty package name")
	}
	path := "/api/get_gp_metadata/" + url.PathEscape(pkg) + "/" + strconv.FormatInt(versionCode, 10)
	resp, err := c.do(ctx, path, nil, "get_gp_metadata")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("androzoo gp_metadata: reading %s/%d: %w", pkg, versionCode, err)
	}
	return json.RawMessage(raw), nil
}

// IsSHA256 reports whether s is a syntactically valid SHA-256.
func IsSHA256(s string) bool { return sha256Re.MatchString(strings.TrimSpace(s)) }
