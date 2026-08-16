package sink

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arman-Chaudhury/siemlet/internal/detect"
)

func alert(rule, key string) detect.Alert {
	return detect.Alert{Rule: rule, Key: key, Count: 5,
		At: time.Date(2026, 8, 13, 22, 0, 0, 0, time.UTC)}
}

func TestSendPostsSlackCompatibleJSON(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()

	w := &Webhook{URL: srv.URL, MinInterval: -1}
	sent, err := w.Send(alert("ssh-brute-force", "203.0.113.7"))
	if err != nil || !sent {
		t.Fatalf("Send() = %v, %v", sent, err)
	}
	var payload struct {
		Text string `json:"text"`
		Rule string `json:"rule"`
		Key  string `json:"key"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("payload not JSON: %v: %s", err, body)
	}
	if payload.Text == "" || payload.Rule != "ssh-brute-force" || payload.Key != "203.0.113.7" {
		t.Errorf("payload = %+v", payload)
	}
}

func TestSendDedupsSameRuleAndKey(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
	}))
	defer srv.Close()

	var drops []string
	w := &Webhook{URL: srv.URL, MinInterval: -1, OnDrop: func(r string) { drops = append(drops, r) }}
	for i := 0; i < 3; i++ {
		if _, err := w.Send(alert("r", "k")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.Send(alert("r", "other-key")); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("server got %d calls, want 2 (dup suppressed, distinct key sent)", got)
	}
	if len(drops) != 2 || drops[0] != DropDedup {
		t.Errorf("drops = %v", drops)
	}
}

func TestSendRateLimitsAcrossKeys(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
	}))
	defer srv.Close()

	now := time.Date(2026, 8, 13, 22, 0, 0, 0, time.UTC)
	var drops []string
	w := &Webhook{URL: srv.URL, MinInterval: time.Second,
		Now:    func() time.Time { return now },
		OnDrop: func(r string) { drops = append(drops, r) }}

	w.Send(alert("r", "k1"))
	w.Send(alert("r", "k2")) // same instant: rate limited
	now = now.Add(2 * time.Second)
	w.Send(alert("r", "k3"))
	if got := calls.Load(); got != 2 {
		t.Fatalf("server got %d calls, want 2", got)
	}
	if len(drops) != 1 || drops[0] != DropRateLimit {
		t.Errorf("drops = %v", drops)
	}
}

func TestSendFailureAllowsRetry(t *testing.T) {
	fail := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			http.Error(w, "boom", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	w := &Webhook{URL: srv.URL, MinInterval: -1}
	if sent, err := w.Send(alert("r", "k")); err == nil || sent {
		t.Fatalf("expected failure, got sent=%v err=%v", sent, err)
	}
	fail = false
	if sent, err := w.Send(alert("r", "k")); err != nil || !sent {
		t.Fatalf("retry after failure: sent=%v err=%v (dedup must not eat it)", sent, err)
	}
}
