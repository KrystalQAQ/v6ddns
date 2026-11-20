// Package cloudflare wraps the subset of the Cloudflare v4 DNS API needed by
// v6ddns: finding one AAAA record and creating or updating it.
//
// It deliberately exposes no delete operation — the DDNS engine must never be
// able to remove a user's DNS record, even after a failed update.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the public Cloudflare API v4 endpoint.
	DefaultBaseURL = "https://api.cloudflare.com/client/v4"
	// DefaultTimeout bounds every request made by a Client.
	DefaultTimeout = 5 * time.Second
	// RecordTypeAAAA is the DNS record type managed by v6ddns.
	RecordTypeAAAA = "AAAA"

	maxResponseBody = 1 << 20 // 1 MiB; enough for any single DNS record response.
)

// ClientAPI is the narrow interface consumed by the DDNS engine. Keeping it
// here lets both the real Client and test doubles be injected without the
// engine depending on HTTP details.
type ClientAPI interface {
	GetRecord(ctx context.Context, zoneID, domain string) (Record, error)
	UpdateRecord(ctx context.Context, zoneID, recordID, content string, ttl int, proxied bool) error
	CreateRecord(ctx context.Context, zoneID, domain, content string, ttl int, proxied bool) error
}

// ErrRecordNotFound is returned by GetRecord when the zone has no AAAA record
// matching the requested name. It is a sentinel so callers can distinguish
// "absent" from a real API failure with errors.Is.
var ErrRecordNotFound = errors.New("cloudflare: AAAA record not found")

// ErrorDetail is one entry of Cloudflare's top-level "errors" array.
type ErrorDetail struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// APIError carries the HTTP status and Cloudflare's own error details. The
// API token is never stored here or rendered by Error.
type APIError struct {
	Operation  string
	StatusCode int
	Details    []ErrorDetail
}

// Error implements error. Token values are redacted as a final safeguard in
// the unlikely event that an upstream error message echoes one back to us.
func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "cloudflare: %s: HTTP %d", e.Operation, e.StatusCode)
	for i, d := range e.Details {
		if i == 0 {
			b.WriteString(": ")
		} else {
			b.WriteString("; ")
		}
		if d.Code != 0 {
			fmt.Fprintf(&b, "code %d: ", d.Code)
		}
		b.WriteString(d.Message)
	}
	return b.String()
}

// Record is the relevant subset of a Cloudflare DNS record.
type Record struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

// Client is a Cloudflare DNS API client. It is safe for concurrent use.
type Client struct {
	token      string
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a Client for the public Cloudflare API using an API token.
// A timeout <= 0 selects DefaultTimeout.
func NewClient(token string, timeout time.Duration) *Client {
	return NewClientWithBaseURL(token, DefaultBaseURL, timeout)
}

// NewClientWithBaseURL creates a Client against a custom endpoint. It is used
// by tests (httptest.Server) and by deployments behind an API proxy.
func NewClientWithBaseURL(token, baseURL string, timeout time.Duration) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Client{
		token:      token,
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: timeout},
	}
}

// apiResponse mirrors Cloudflare's standard response envelope. The generic
// Result type keeps list and single-record endpoints type-safe.
type apiResponse[T any] struct {
	Success bool          `json:"success"`
	Errors  []ErrorDetail `json:"errors"`
	Result  T             `json:"result"`
}

type recordPatch struct {
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

type recordCreate struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

// GetRecord returns the first AAAA record whose name matches domain. When no
// such record exists it returns ErrRecordNotFound (wrapped with the operation
// context); any other failure is an *APIError or a transport error.
func (c *Client) GetRecord(ctx context.Context, zoneID, domain string) (Record, error) {
	path := fmt.Sprintf("/zones/%s/dns_records?%s", url.PathEscape(zoneID), url.Values{
		"type":     {RecordTypeAAAA},
		"name":     {domain},
		"per_page": {"1"},
	}.Encode())

	var out apiResponse[[]Record]
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return Record{}, err
	}
	if len(out.Result) == 0 {
		return Record{}, fmt.Errorf("get AAAA record for %s: %w", domain, ErrRecordNotFound)
	}
	return out.Result[0], nil
}

// UpdateRecord patches the content, TTL and proxy flag of an existing record.
// It never issues a DELETE request.
func (c *Client) UpdateRecord(ctx context.Context, zoneID, recordID, content string, ttl int, proxied bool) error {
	path := fmt.Sprintf("/zones/%s/dns_records/%s",
		url.PathEscape(zoneID), url.PathEscape(recordID))
	return c.do(ctx, http.MethodPatch, path, recordPatch{
		Content: content,
		TTL:     ttl,
		Proxied: proxied,
	}, &apiResponse[Record]{})
}

// CreateRecord adds a new AAAA record to the zone.
func (c *Client) CreateRecord(ctx context.Context, zoneID, domain, content string, ttl int, proxied bool) error {
	path := fmt.Sprintf("/zones/%s/dns_records", url.PathEscape(zoneID))
	return c.do(ctx, http.MethodPost, path, recordCreate{
		Type:    RecordTypeAAAA,
		Name:    domain,
		Content: content,
		TTL:     ttl,
		Proxied: proxied,
	}, &apiResponse[Record]{})
}

// do performs one authenticated request and decodes the standard envelope.
func (c *Client) do(ctx context.Context, method, path string, payload, out any) error {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("cloudflare: encode %s request: %w", method, err)
		}
		body = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("cloudflare: build %s request: %s", method, c.redact(err.Error()))
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare: %s request: %s", method, c.redact(err.Error()))
	}
	defer resp.Body.Close()

	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if readErr != nil {
		return fmt.Errorf("cloudflare: %s read response: %s", method, c.redact(readErr.Error()))
	}

	var envelope apiResponse[json.RawMessage]
	if json.Unmarshal(raw, &envelope) != nil {
		// A malformed body is still worth reporting with its status code.
		return &APIError{Operation: method, StatusCode: resp.StatusCode}
	}

	op := operationName(method, path)
	if resp.StatusCode < 200 || resp.StatusCode > 299 || !envelope.Success {
		apiErr := &APIError{Operation: op, StatusCode: resp.StatusCode}
		if len(envelope.Errors) > 0 {
			apiErr.Details = envelope.Errors
			for i := range apiErr.Details {
				apiErr.Details[i].Message = c.redact(apiErr.Details[i].Message)
			}
		}
		return apiErr
	}

	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("cloudflare: %s decode response: %s", op, c.redact(err.Error()))
		}
	}
	return nil
}

func operationName(method, path string) string {
	switch method {
	case http.MethodGet:
		return "get record"
	case http.MethodPatch:
		return "update record"
	case http.MethodPost:
		return "create record"
	default:
		return strings.ToLower(method) + " " + path
	}
}

// redact guarantees the token never reaches an error string, even if an
// upstream message or a URL happens to contain it.
func (c *Client) redact(s string) string {
	if c.token == "" {
		return s
	}
	return strings.ReplaceAll(s, c.token, "***")
}
