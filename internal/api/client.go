// Package api is the HTTP client for the Oka Cyber agent API.
package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/okanetsolutions/oka-cyber-agent/internal/config"
)

const (
	BasePath = "/cyber-agent/v1"

	// MaxBodyBytes is the server's limit, applied to the request body both before and after gzip.
	MaxBodyBytes = 5 << 20

	maxResponseBytes = 1 << 20
	maxErrorBody     = 512
	maxRetryAfter    = 15 * time.Minute
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrBodyTooLarge = fmt.Errorf("request body is larger than the server limit of %d bytes", MaxBodyBytes)
)

type HTTPError struct {
	Method     string
	Path       string
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("%s %s: HTTP %d", e.Method, e.Path, e.StatusCode)
	}
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.Method, e.Path, e.StatusCode, e.Body)
}

type Options struct {
	Token        Secret
	InsecureDev  bool
	AgentVersion string
	HTTPClient   *http.Client
	MaxAttempts  int
	BaseDelay    time.Duration
	MaxDelay     time.Duration
	Sleep        func(ctx context.Context, d time.Duration) error
}

type Client struct {
	base        *url.URL
	token       Secret
	userAgent   string
	http        *http.Client
	maxAttempts int
	baseDelay   time.Duration
	maxDelay    time.Duration
	sleep       func(ctx context.Context, d time.Duration) error
}

func New(baseURL string, o Options) (*Client, error) {
	if err := config.ValidateURL(baseURL, o.InsecureDev); err != nil {
		return nil, err
	}
	base, err := url.Parse(strings.TrimRight(baseURL, "/") + BasePath)
	if err != nil {
		return nil, err
	}
	c := &Client{
		base:        base,
		token:       o.Token,
		userAgent:   fmt.Sprintf("oka-cyber-agent/%s (%s; %s)", o.AgentVersion, runtime.GOOS, runtime.GOARCH),
		http:        o.HTTPClient,
		maxAttempts: o.MaxAttempts,
		baseDelay:   o.BaseDelay,
		maxDelay:    o.MaxDelay,
		sleep:       o.Sleep,
	}
	if c.http == nil {
		c.http = defaultHTTPClient()
	}
	if c.maxAttempts <= 0 {
		c.maxAttempts = 5
	}
	if c.baseDelay <= 0 {
		c.baseDelay = time.Second
	}
	if c.maxDelay <= 0 {
		c.maxDelay = time.Minute
	}
	if c.sleep == nil {
		c.sleep = sleepContext
	}
	return c, nil
}

func (c *Client) String() string   { return "api.Client(" + c.base.String() + ")" }
func (c *Client) GoString() string { return c.String() }

func defaultHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{
		Transport: transport,
		Timeout:   time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Enroll exchanges a one time enrollment token for the agent token. It is not idempotent (the server creates
// a server record), so it is only retried when the request certainly did not reach the server or was refused
// before processing (429, 503).
func (c *Client) Enroll(ctx context.Context, req EnrollRequest) (EnrollResponse, error) {
	var resp EnrollResponse
	err := c.do(ctx, http.MethodPost, "/enroll", req, false, &resp)
	if errors.Is(err, ErrUnauthorized) {
		return resp, fmt.Errorf("enrollment token is invalid, expired, revoked or used up: %w", err)
	}
	if err == nil && (resp.AgentToken == "" || resp.ServerID == "") {
		return resp, errors.New("enroll: response is missing server_id or agent_token")
	}
	return resp, err
}

func (c *Client) Heartbeat(ctx context.Context, req HeartbeatRequest) (HeartbeatResponse, error) {
	var resp HeartbeatResponse
	return resp, c.do(ctx, http.MethodPost, "/heartbeat", req, true, &resp)
}

// PutInventory sends an already encoded snapshot, so the caller hashes exactly the bytes that are sent.
func (c *Client) PutInventory(ctx context.Context, snapshot json.RawMessage) (InventoryResponse, error) {
	var resp InventoryResponse
	return resp, c.do(ctx, http.MethodPut, "/inventory", snapshot, true, &resp)
}

func (c *Client) PostLogs(ctx context.Context, batch LogBatchRequest) (LogBatchResponse, error) {
	var resp LogBatchResponse
	return resp, c.do(ctx, http.MethodPost, "/logs", batch, true, &resp)
}

func (c *Client) do(ctx context.Context, method, path string, payload any, idempotent bool, out any) error {
	body, err := encodeBody(payload)
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 1; ; attempt++ {
		delay, retry, err := c.attempt(ctx, method, path, body, idempotent, out)
		if err == nil {
			return nil
		}
		lastErr = err
		if !retry || attempt >= c.maxAttempts {
			return lastErr
		}
		if delay <= 0 {
			delay = c.backoff(attempt)
		}
		if err := c.sleep(ctx, delay); err != nil {
			return err
		}
	}
}

func (c *Client) attempt(ctx context.Context, method, path string, body []byte, idempotent bool, out any) (time.Duration, bool, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+path, bytes.NewReader(body))
	if err != nil {
		return 0, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+string(c.token))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, false, ctx.Err()
		}
		return 0, idempotent || isDialError(err), fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return 0, idempotent, fmt.Errorf("%s %s: read response: %w", method, path, err)
	}

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		if out == nil || len(bytes.TrimSpace(data)) == 0 {
			return 0, false, nil
		}
		if err := json.Unmarshal(data, out); err != nil {
			return 0, false, fmt.Errorf("%s %s: decode response: %w", method, path, err)
		}
		return 0, false, nil
	case resp.StatusCode == http.StatusUnauthorized:
		return 0, false, fmt.Errorf("%s %s: %w", method, path, ErrUnauthorized)
	}

	httpErr := &HTTPError{Method: method, Path: path, StatusCode: resp.StatusCode, Body: errorBody(data)}
	retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable ||
		(idempotent && resp.StatusCode >= 500)
	if !retryable {
		return 0, false, httpErr
	}
	return retryAfter(resp.Header.Get("Retry-After"), time.Now()), true, httpErr
}

func encodeBody(payload any) ([]byte, error) {
	raw, ok := payload.(json.RawMessage)
	if !ok {
		var err error
		if raw, err = json.Marshal(payload); err != nil {
			return nil, err
		}
	}
	if len(raw) > MaxBodyBytes {
		return nil, ErrBodyTooLarge
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func errorBody(data []byte) string {
	var decoded struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(data, &decoded) == nil && decoded.Message != "" {
		data = []byte(decoded.Message)
	}
	s := strings.TrimSpace(strings.ToValidUTF8(string(data), ""))
	if len(s) > maxErrorBody {
		s = s[:maxErrorBody]
	}
	return s
}

// backoff is exponential with full jitter: a random delay up to base * 2^(attempt-1), capped at maxDelay.
func (c *Client) backoff(attempt int) time.Duration {
	ceiling := c.maxDelay
	if shift := attempt - 1; shift < 30 {
		if d := c.baseDelay << shift; d > 0 && d < ceiling {
			ceiling = d
		}
	}
	return time.Duration(rand.Int64N(int64(ceiling)) + 1)
}

// retryAfter parses a Retry-After header given in seconds or as an HTTP date.
func retryAfter(header string, now time.Time) time.Duration {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0
	}
	var d time.Duration
	if seconds, err := strconv.Atoi(header); err == nil {
		d = time.Duration(seconds) * time.Second
	} else if at, err := http.ParseTime(header); err == nil {
		d = at.Sub(now)
	}
	if d <= 0 {
		return 0
	}
	return min(d, maxRetryAfter)
}

func isDialError(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
