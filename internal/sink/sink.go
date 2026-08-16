// Package sink delivers alerts to external systems.
package sink

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Arman-Chaudhury/siemlet/internal/detect"
)

// Drop reasons reported to OnDrop.
const (
	DropDedup     = "dedup"
	DropRateLimit = "rate_limit"
)

// Webhook POSTs alerts as JSON. The payload carries a Slack-compatible
// "text" field plus the structured alert. Repeats of the same (rule, key)
// within DedupTTL are suppressed, and a global MinInterval between sends
// caps outbound volume; suppressed alerts are reported via OnDrop.
type Webhook struct {
	URL         string
	Client      *http.Client  // default: 10s-timeout client
	DedupTTL    time.Duration // default 10m
	MinInterval time.Duration // default 1s; 0 uses the default, negative disables
	OnDrop      func(reason string)
	Now         func() time.Time // test hook

	mu        sync.Mutex
	lastByKey map[string]time.Time
	lastSend  time.Time
}

func (w *Webhook) defaults() (*http.Client, time.Duration, time.Duration, func() time.Time) {
	client := w.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	dedup := w.DedupTTL
	if dedup == 0 {
		dedup = 10 * time.Minute
	}
	min := w.MinInterval
	if min == 0 {
		min = time.Second
	}
	now := w.Now
	if now == nil {
		now = time.Now
	}
	return client, dedup, min, now
}

// Send delivers one alert. It returns (false, nil) when the alert was
// suppressed by dedup or rate limiting, and (false, err) on delivery failure
// (the alert stays eligible for retry by the next occurrence).
func (w *Webhook) Send(a detect.Alert) (bool, error) {
	client, dedup, minInterval, now := w.defaults()
	key := a.Rule + "\x00" + a.Key

	w.mu.Lock()
	t := now()
	if last, ok := w.lastByKey[key]; ok && t.Sub(last) < dedup {
		w.mu.Unlock()
		w.drop(DropDedup)
		return false, nil
	}
	if minInterval > 0 && !w.lastSend.IsZero() && t.Sub(w.lastSend) < minInterval {
		w.mu.Unlock()
		w.drop(DropRateLimit)
		return false, nil
	}
	if w.lastByKey == nil {
		w.lastByKey = make(map[string]time.Time)
	}
	// Reserve the slot before the network call so concurrent senders
	// don't duplicate; on failure the reservation is rolled back.
	w.lastByKey[key] = t
	w.lastSend = t
	w.mu.Unlock()

	payload, err := json.Marshal(struct {
		Text  string `json:"text"`
		Rule  string `json:"rule"`
		Key   string `json:"key"`
		Count int    `json:"count"`
		At    string `json:"at"`
		Raw   string `json:"raw,omitempty"`
	}{
		Text:  "siemlet " + a.String(),
		Rule:  a.Rule,
		Key:   a.Key,
		Count: a.Count,
		At:    a.At.UTC().Format(time.RFC3339),
		Raw:   a.Last.Raw,
	})
	if err != nil {
		return false, err
	}
	resp, err := client.Post(w.URL, "application/json", bytes.NewReader(payload))
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			err = fmt.Errorf("webhook returned %s", resp.Status)
		}
	}
	if err != nil {
		w.mu.Lock()
		delete(w.lastByKey, key)
		w.mu.Unlock()
		return false, err
	}
	return true, nil
}

func (w *Webhook) drop(reason string) {
	if w.OnDrop != nil {
		w.OnDrop(reason)
	}
}
