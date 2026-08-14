package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExposition(t *testing.T) {
	r := New()
	r.Inc("siemlet_events_ingested_total")
	r.Add("siemlet_events_ingested_total", 41)
	r.Inc("siemlet_alerts_fired_total", "rule", "ssh-brute-force")
	r.Inc("siemlet_alerts_fired_total", "rule", "ssh-brute-force")
	r.Inc("siemlet_alerts_fired_total", "rule", "password-spray")

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))

	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Errorf("Content-Type = %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"# TYPE siemlet_events_ingested_total counter\n",
		"siemlet_events_ingested_total 42\n",
		`siemlet_alerts_fired_total{rule="ssh-brute-force"} 2` + "\n",
		`siemlet_alerts_fired_total{rule="password-spray"} 1` + "\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("exposition missing %q:\n%s", want, body)
		}
	}
}

func TestValueAndEscaping(t *testing.T) {
	r := New()
	r.Inc("c", "k", `a"b\c`)
	if got := r.Value("c", "k", `a"b\c`); got != 1 {
		t.Errorf("Value = %d", got)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `c{k="a\"b\\c"} 1`) {
		t.Errorf("escaping wrong:\n%s", rec.Body.String())
	}
}
