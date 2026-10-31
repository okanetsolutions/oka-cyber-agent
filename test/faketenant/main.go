// Command faketenant is a minimal stand in for the Oka Cyber agent API, used by the install tests in CI.
// It also serves release files from a directory, so install.sh can be tested without a GitHub release.
package main

import (
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
)

type tenant struct {
	enrollmentToken string

	logSources    []string
	flushInterval int

	mu                    sync.Mutex
	agentTokens           map[string]bool
	logBatches            int
	logEvents             []json.RawMessage
	enrollments           int
	heartbeats            int
	inventories           int
	lastInventoryPackages int
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8090", "listen address")
	files := flag.String("files", ".", "directory served under /files/")
	enrollmentToken := flag.String("enrollment-token", "test-enrollment-token", "the only enrollment token accepted")
	logSources := flag.String("log-sources", "", "comma separated log sources enabled in heartbeat responses")
	flushInterval := flag.Int("flush-interval", 5, "flush_interval_seconds sent to the agent")
	flag.Parse()

	t := &tenant{enrollmentToken: *enrollmentToken, agentTokens: map[string]bool{}, logSources: []string{}, flushInterval: *flushInterval}
	if *logSources != "" {
		t.logSources = strings.Split(*logSources, ",")
	}
	mux := http.NewServeMux()
	mux.Handle("GET /files/", http.StripPrefix("/files/", http.FileServer(http.Dir(*files))))
	mux.HandleFunc("POST /cyber-agent/v1/enroll", t.enroll)
	mux.HandleFunc("POST /cyber-agent/v1/heartbeat", t.authenticated(t.heartbeat))
	mux.HandleFunc("PUT /cyber-agent/v1/inventory", t.authenticated(t.inventory))
	mux.HandleFunc("POST /cyber-agent/v1/logs", t.authenticated(t.logs))
	mux.HandleFunc("GET /log-events", t.events)
	mux.HandleFunc("GET /stats", t.stats)
	log.Printf("listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func decode(r *http.Request, v any) error {
	body := io.Reader(r.Body)
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			return err
		}
		body = zr
	}
	return json.NewDecoder(body).Decode(v)
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (t *tenant) enroll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EnrollmentToken string `json:"enrollment_token"`
		Hostname        string `json:"hostname"`
	}
	if err := decode(r, &req); err != nil || req.Hostname == "" {
		reply(w, http.StatusUnprocessableEntity, map[string]string{"message": "invalid enrollment"})
		return
	}
	if req.EnrollmentToken != t.enrollmentToken {
		reply(w, http.StatusUnauthorized, map[string]string{"message": "Unauthenticated."})
		return
	}
	t.mu.Lock()
	t.enrollments++
	id := t.enrollments
	token := fmt.Sprintf("test-agent-token-%d", id)
	t.agentTokens[token] = true
	t.mu.Unlock()
	reply(w, http.StatusCreated, map[string]any{"server_id": id, "agent_token": token, "report_interval_seconds": 60})
}

func (t *tenant) authenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		t.mu.Lock()
		ok := t.agentTokens[token]
		t.mu.Unlock()
		if !ok {
			reply(w, http.StatusUnauthorized, map[string]string{"message": "Unauthenticated."})
			return
		}
		next(w, r)
	}
}

func (t *tenant) heartbeat(w http.ResponseWriter, _ *http.Request) {
	t.mu.Lock()
	t.heartbeats++
	t.mu.Unlock()
	reply(w, http.StatusOK, map[string]any{"report_interval_seconds": 60, "log_collection": t.logCollection()})
}

func (t *tenant) logCollection() map[string]any {
	return map[string]any{"sources": t.logSources, "flush_interval_seconds": t.flushInterval}
}

func (t *tenant) logs(w http.ResponseWriter, r *http.Request) {
	var batch struct {
		BatchID string            `json:"batch_id"`
		Events  []json.RawMessage `json:"events"`
	}
	if err := decode(r, &batch); err != nil || len(batch.BatchID) != 36 || batch.Events == nil {
		reply(w, http.StatusUnprocessableEntity, map[string]string{"message": "invalid batch"})
		return
	}
	t.mu.Lock()
	t.logBatches++
	t.logEvents = append(t.logEvents, batch.Events...)
	t.mu.Unlock()
	reply(w, http.StatusOK, map[string]any{"accepted": len(batch.Events), "log_collection": t.logCollection()})
}

func (t *tenant) events(w http.ResponseWriter, _ *http.Request) {
	t.mu.Lock()
	defer t.mu.Unlock()
	reply(w, http.StatusOK, t.logEvents)
}

func (t *tenant) inventory(w http.ResponseWriter, r *http.Request) {
	var snapshot struct {
		Packages []json.RawMessage `json:"packages"`
	}
	if err := decode(r, &snapshot); err != nil {
		reply(w, http.StatusUnprocessableEntity, map[string]string{"message": "invalid inventory"})
		return
	}
	t.mu.Lock()
	t.inventories++
	t.lastInventoryPackages = len(snapshot.Packages)
	t.mu.Unlock()
	reply(w, http.StatusOK, map[string]any{"changed": true, "report_interval_seconds": 60})
}

func (t *tenant) stats(w http.ResponseWriter, _ *http.Request) {
	t.mu.Lock()
	defer t.mu.Unlock()
	reply(w, http.StatusOK, map[string]int{
		"enrollments":             t.enrollments,
		"heartbeats":              t.heartbeats,
		"inventories":             t.inventories,
		"last_inventory_packages": t.lastInventoryPackages,
		"log_batches":             t.logBatches,
		"log_events":              len(t.logEvents),
	})
}
