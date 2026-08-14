package web

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Arman-Chaudhury/siemlet/internal/detect"
	"github.com/Arman-Chaudhury/siemlet/internal/metrics"
	"github.com/Arman-Chaudhury/siemlet/internal/parse"
	"github.com/Arman-Chaudhury/siemlet/internal/store"
)

func setup(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	reg := metrics.New()
	reg.Inc("siemlet_events_ingested_total")
	return New(db, reg, 5), db
}

func TestDashboardRendersAlerts(t *testing.T) {
	srv, db := setup(t)
	now := time.Now().UTC()
	db.InsertEvent(parse.Event{Time: now, Kind: parse.AuthFail, IP: "203.0.113.7", Raw: "x"})
	db.InsertAlert(detect.Alert{Rule: "ssh-brute-force", Key: "203.0.113.7", Count: 5,
		At: now, Last: parse.Event{Raw: "Failed password for root"}})

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 {
		t.Fatalf("GET / = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"ssh-brute-force", "203.0.113.7", "5 rules loaded"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
}

func TestDashboardEmptyStateAndRoutes(t *testing.T) {
	srv, _ := setup(t)
	h := srv.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "no alerts yet") {
		t.Errorf("empty dashboard = %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 {
		t.Errorf("healthz = %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "siemlet_events_ingested_total 1") {
		t.Errorf("metrics = %d: %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/nope", nil))
	if rec.Code != 404 {
		t.Errorf("unknown path = %d, want 404", rec.Code)
	}
}

func TestAPIAlertsJSON(t *testing.T) {
	srv, db := setup(t)
	db.InsertAlert(detect.Alert{Rule: "r", Key: "k", Count: 2, At: time.Now()})

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/alerts", nil))
	if rec.Code != 200 {
		t.Fatalf("api = %d", rec.Code)
	}
	var rows []store.AlertRow
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if len(rows) != 1 || rows[0].Rule != "r" {
		t.Errorf("rows = %+v", rows)
	}
}
