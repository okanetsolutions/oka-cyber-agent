package api

import (
	"compress/gzip"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/okanetsolutions/oka-cyber-agent/internal/logs"
)

type recordedRequest struct {
	method, path, authorization, userAgent, encoding string
	body                                             []byte
}

type recorder struct {
	mu       sync.Mutex
	requests []recordedRequest
}

func (r *recorder) all() []recordedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.requests)
}

func (r *recorder) count() int { return len(r.all()) }

func testServer(t *testing.T, handler func(w http.ResponseWriter, r recordedRequest, n int)) (*httptest.Server, *recorder) {
	t.Helper()
	requests := &recorder{}
	var count atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Errorf("request body is not gzip: %v", err)
			return
		}
		body, err := io.ReadAll(zr)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		rec := recordedRequest{r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("User-Agent"), r.Header.Get("Content-Encoding"), body}
		requests.mu.Lock()
		requests.requests = append(requests.requests, rec)
		requests.mu.Unlock()
		handler(w, rec, int(count.Add(1)))
	}))
	t.Cleanup(srv.Close)
	return srv, requests
}

type sleeps struct{ delays []time.Duration }

func (s *sleeps) sleep(_ context.Context, d time.Duration) error {
	s.delays = append(s.delays, d)
	return nil
}

func newClient(t *testing.T, srv *httptest.Server, token Secret, s *sleeps) *Client {
	t.Helper()
	client := defaultHTTPClient()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	client.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
	c, err := New(srv.URL+"/", Options{Token: token, AgentVersion: "1.2.3", HTTPClient: client, MaxAttempts: 3, Sleep: s.sleep})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprint(w, body)
}

func TestEnrollSendsFactsWithoutBearerAndDecodesNumericServerID(t *testing.T) {
	srv, requests := testServer(t, func(w http.ResponseWriter, _ recordedRequest, _ int) {
		writeJSON(w, http.StatusCreated, `{"server_id":42,"agent_token":"agent-secret","report_interval_seconds":300}`)
	})
	c := newClient(t, srv, "", &sleeps{})
	resp, err := c.Enroll(context.Background(), EnrollRequest{EnrollmentToken: "enroll-secret", Hostname: "web-1", OSFamily: "debian", AgentVersion: "1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.ServerID != "42" || resp.AgentToken != "agent-secret" || resp.ReportIntervalSeconds != 300 {
		t.Fatalf("resp = %+v", resp)
	}
	r := requests.all()[0]
	if r.method != http.MethodPost || r.path != "/cyber-agent/v1/enroll" || r.authorization != "" || r.encoding != "gzip" {
		t.Fatalf("request = %+v", r)
	}
	if !strings.HasPrefix(r.userAgent, "oka-cyber-agent/1.2.3 ") {
		t.Fatalf("user agent = %q", r.userAgent)
	}
	var sent map[string]any
	if err := json.Unmarshal(r.body, &sent); err != nil {
		t.Fatal(err)
	}
	if sent["enrollment_token"] != "enroll-secret" || sent["hostname"] != "web-1" || sent["agent_version"] != "1.2.3" {
		t.Fatalf("body = %v", sent)
	}
}

func TestEnrollIsNotRetriedOnInvalidTokenOrServerError(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusInternalServerError, http.StatusBadGateway} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv, requests := testServer(t, func(w http.ResponseWriter, _ recordedRequest, _ int) {
				writeJSON(w, status, `{"message":"nope"}`)
			})
			_, err := newClient(t, srv, "", &sleeps{}).Enroll(context.Background(), EnrollRequest{EnrollmentToken: "x", Hostname: "h"})
			if err == nil || requests.count() != 1 {
				t.Fatalf("err = %v after %d requests, want one failed request", err, requests.count())
			}
			if status == http.StatusUnauthorized && !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("err = %v, want ErrUnauthorized", err)
			}
		})
	}
}

func TestEnrollRetriesWhenServiceIsUnavailable(t *testing.T) {
	srv, requests := testServer(t, func(w http.ResponseWriter, _ recordedRequest, n int) {
		if n == 1 {
			writeJSON(w, http.StatusServiceUnavailable, `{}`)
			return
		}
		writeJSON(w, http.StatusCreated, `{"server_id":"srv_1","agent_token":"a","report_interval_seconds":300}`)
	})
	resp, err := newClient(t, srv, "", &sleeps{}).Enroll(context.Background(), EnrollRequest{EnrollmentToken: "x", Hostname: "h"})
	if err != nil || resp.ServerID != "srv_1" || requests.count() != 2 {
		t.Fatalf("resp = %+v, err = %v, requests = %d", resp, err, requests.count())
	}
}

func TestEnrollRejectsResponseWithoutToken(t *testing.T) {
	srv, _ := testServer(t, func(w http.ResponseWriter, _ recordedRequest, _ int) {
		writeJSON(w, http.StatusCreated, `{"server_id":1}`)
	})
	if _, err := newClient(t, srv, "", &sleeps{}).Enroll(context.Background(), EnrollRequest{}); err == nil {
		t.Fatal("want an error for a response without agent_token")
	}
}

func TestHeartbeatSendsBearerAndHonoursRetryAfter(t *testing.T) {
	srv, requests := testServer(t, func(w http.ResponseWriter, _ recordedRequest, n int) {
		if n == 1 {
			w.Header().Set("Retry-After", "7")
			writeJSON(w, http.StatusTooManyRequests, `{}`)
			return
		}
		writeJSON(w, http.StatusOK, `{"report_interval_seconds":600}`)
	})
	s := &sleeps{}
	resp, err := newClient(t, srv, "agent-secret", s).Heartbeat(context.Background(), HeartbeatRequest{AgentVersion: "1.2.3"})
	if err != nil || resp.ReportIntervalSeconds != 600 {
		t.Fatalf("resp = %+v, err = %v", resp, err)
	}
	if len(s.delays) != 1 || s.delays[0] != 7*time.Second {
		t.Fatalf("slept %v, want [7s]", s.delays)
	}
	for _, r := range requests.all() {
		if r.authorization != "Bearer agent-secret" || r.path != "/cyber-agent/v1/heartbeat" {
			t.Fatalf("request = %+v", r)
		}
	}
}

func TestServerErrorsAreRetriedWithBackoffUpToMaxAttempts(t *testing.T) {
	srv, requests := testServer(t, func(w http.ResponseWriter, _ recordedRequest, _ int) {
		writeJSON(w, http.StatusBadGateway, `<html>bad gateway</html>`)
	})
	s := &sleeps{}
	_, err := newClient(t, srv, "agent-secret", s).Heartbeat(context.Background(), HeartbeatRequest{})
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("err = %v, want HTTP 502", err)
	}
	if requests.count() != 3 || len(s.delays) != 2 {
		t.Fatalf("requests = %d, sleeps = %v, want 3 attempts and 2 sleeps", requests.count(), s.delays)
	}
	if s.delays[0] > time.Second || s.delays[1] > 2*time.Second {
		t.Fatalf("delays %v exceed the exponential ceilings 1s, 2s", s.delays)
	}
}

func TestUnauthorizedIsNotRetried(t *testing.T) {
	srv, requests := testServer(t, func(w http.ResponseWriter, _ recordedRequest, _ int) {
		writeJSON(w, http.StatusUnauthorized, `{"message":"Unauthenticated."}`)
	})
	_, err := newClient(t, srv, "revoked", &sleeps{}).Heartbeat(context.Background(), HeartbeatRequest{})
	if !errors.Is(err, ErrUnauthorized) || requests.count() != 1 {
		t.Fatalf("err = %v after %d requests", err, requests.count())
	}
}

func TestValidationErrorIsReturnedWithoutRetryOrRequestBody(t *testing.T) {
	srv, requests := testServer(t, func(w http.ResponseWriter, _ recordedRequest, _ int) {
		writeJSON(w, http.StatusUnprocessableEntity, `{"message":"The packages.0.name field is required.","errors":{}}`)
	})
	_, err := newClient(t, srv, "agent-secret", &sleeps{}).PutInventory(context.Background(), json.RawMessage(`{"packages":[{"secret":"payload-value"}]}`))
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusUnprocessableEntity || httpErr.Body != "The packages.0.name field is required." {
		t.Fatalf("err = %#v", err)
	}
	if requests.count() != 1 {
		t.Fatalf("requests = %d, want 1", requests.count())
	}
	if strings.Contains(err.Error(), "payload-value") || strings.Contains(err.Error(), "agent-secret") {
		t.Fatalf("error %q leaks the request", err)
	}
}

func TestPutInventorySendsTheExactSnapshotBytes(t *testing.T) {
	snapshot := json.RawMessage(`{"os":{},"packages":[]}`)
	srv, requests := testServer(t, func(w http.ResponseWriter, _ recordedRequest, _ int) {
		writeJSON(w, http.StatusOK, `{"changed":true,"report_interval_seconds":300}`)
	})
	resp, err := newClient(t, srv, "agent-secret", &sleeps{}).PutInventory(context.Background(), snapshot)
	if err != nil || !resp.Changed {
		t.Fatalf("resp = %+v, err = %v", resp, err)
	}
	r := requests.all()[0]
	if r.method != http.MethodPut || r.path != "/cyber-agent/v1/inventory" || string(r.body) != string(snapshot) {
		t.Fatalf("request = %s %s %s", r.method, r.path, r.body)
	}
}

func TestBodyOverServerLimitIsNotSent(t *testing.T) {
	srv, requests := testServer(t, func(w http.ResponseWriter, _ recordedRequest, _ int) {
		writeJSON(w, http.StatusOK, `{}`)
	})
	big := json.RawMessage(`"` + strings.Repeat("a", MaxBodyBytes) + `"`)
	if _, err := newClient(t, srv, "t", &sleeps{}).PutInventory(context.Background(), big); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("err = %v, want ErrBodyTooLarge", err)
	}
	if requests.count() != 0 {
		t.Fatal("an oversized body must not be sent")
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	srv, requests := testServer(t, func(w http.ResponseWriter, r recordedRequest, _ int) {
		if r.path == "/elsewhere" {
			writeJSON(w, http.StatusOK, `{}`)
			return
		}
		w.Header().Set("Location", "/elsewhere")
		w.WriteHeader(http.StatusFound)
	})
	_, err := newClient(t, srv, "agent-secret", &sleeps{}).Heartbeat(context.Background(), HeartbeatRequest{})
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusFound {
		t.Fatalf("err = %v, want HTTP 302", err)
	}
	if requests.count() != 1 {
		t.Fatalf("requests = %d, the redirect must not be followed", requests.count())
	}
}

func TestTimeoutsAreRetriedForIdempotentRequests(t *testing.T) {
	release := make(chan struct{})
	srv, requests := testServer(t, func(w http.ResponseWriter, _ recordedRequest, _ int) {
		<-release
	})
	t.Cleanup(func() { close(release) })
	c := newClient(t, srv, "t", &sleeps{})
	c.http.Timeout = 50 * time.Millisecond
	if _, err := c.Heartbeat(context.Background(), HeartbeatRequest{}); err == nil {
		t.Fatal("want a timeout error")
	}
	if requests.count() != 3 {
		t.Fatalf("requests = %d, want 3 attempts", requests.count())
	}
}

func TestNewRejectsPlainHTTPUnlessInsecureDev(t *testing.T) {
	if _, err := New("http://acme.oka.example", Options{}); err == nil {
		t.Fatal("plain http must be rejected")
	}
	if _, err := New("http://localhost:8000", Options{InsecureDev: true}); err != nil {
		t.Fatalf("insecure dev: %v", err)
	}
}

func TestSecretsNeverFormat(t *testing.T) {
	req := EnrollRequest{EnrollmentToken: "enroll-secret", Hostname: "web-1"}
	resp := EnrollResponse{AgentToken: "agent-secret"}
	c, err := New("https://acme.oka.example", Options{Token: "agent-secret"})
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{fmt.Sprintf("%v %+v %#v %s", req, req, req, req.EnrollmentToken), fmt.Sprintf("%v %+v %#v", resp, resp, resp), fmt.Sprintf("%v %+v %#v", c, c, c)} {
		if strings.Contains(out, "secret") {
			t.Fatalf("formatted output leaks a token: %s", out)
		}
	}
}

func TestRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	tests := map[string]time.Duration{
		"":                              0,
		"30":                            30 * time.Second,
		"-5":                            0,
		"abc":                           0,
		"86400":                         maxRetryAfter,
		"Sat, 31 Oct 2026 12:01:00 GMT": time.Minute,
		"Sat, 31 Oct 2026 11:00:00 GMT": 0,
	}
	for header, want := range tests {
		if got := retryAfter(header, now); got != want {
			t.Errorf("retryAfter(%q) = %v, want %v", header, got, want)
		}
	}
}

func TestBackoffStaysWithinCeiling(t *testing.T) {
	c, err := New("https://acme.oka.example", Options{BaseDelay: time.Second, MaxDelay: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 64; attempt++ {
		ceiling := min(time.Second<<min(attempt-1, 30), 10*time.Second)
		for range 50 {
			if d := c.backoff(attempt); d <= 0 || d > ceiling {
				t.Fatalf("backoff(%d) = %v, want (0, %v]", attempt, d, ceiling)
			}
		}
	}
}

func TestPostLogsSendsTheBatchAndReadsTheConfiguration(t *testing.T) {
	srv, requests := testServer(t, func(w http.ResponseWriter, _ recordedRequest, _ int) {
		writeJSON(w, http.StatusOK, `{"accepted":1,"log_collection":{"sources":["auth"],"flush_interval_seconds":30}}`)
	})
	batch := LogBatchRequest{
		BatchID:        "0b8f5d0e-3c1a-4c55-9f43-2f1d0f0b6a11",
		Events:         []logs.Event{{Source: "auth", Kind: "sudo_command", Count: 1, Message: "m"}},
		SkippedSources: []logs.SkippedSource{{Source: "web", Path: "/var/log/nginx", Reason: "not_found"}},
		DroppedEvents:  3,
	}
	resp, err := newClient(t, srv, "agent-secret", &sleeps{}).PostLogs(context.Background(), batch)
	if err != nil || resp.Accepted != 1 || resp.LogCollection == nil || resp.LogCollection.Sources[0] != "auth" {
		t.Fatalf("resp = %+v, err = %v", resp, err)
	}
	r := requests.all()[0]
	var sent map[string]any
	if err := json.Unmarshal(r.body, &sent); err != nil {
		t.Fatal(err)
	}
	if r.method != http.MethodPost || r.path != "/cyber-agent/v1/logs" || sent["batch_id"] != batch.BatchID || sent["dropped_events"] != float64(3) || len(sent["events"].([]any)) != 1 || len(sent["skipped_sources"].([]any)) != 1 {
		t.Fatalf("request = %s %s %s", r.method, r.path, r.body)
	}
}

func TestHeartbeatReadsLogCollection(t *testing.T) {
	srv, _ := testServer(t, func(w http.ResponseWriter, _ recordedRequest, _ int) {
		writeJSON(w, http.StatusOK, `{"report_interval_seconds":300,"log_collection":{"sources":[],"flush_interval_seconds":30}}`)
	})
	resp, err := newClient(t, srv, "agent-secret", &sleeps{}).Heartbeat(context.Background(), HeartbeatRequest{})
	if err != nil || resp.LogCollection == nil || len(resp.LogCollection.Sources) != 0 {
		t.Fatalf("resp = %+v, err = %v", resp, err)
	}
}
