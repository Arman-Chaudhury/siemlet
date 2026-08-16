package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Arman-Chaudhury/siemlet/internal/detect"
	"github.com/Arman-Chaudhury/siemlet/internal/parse"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestRoundTrip(t *testing.T) {
	s := open(t)
	t0 := time.Date(2026, 8, 13, 22, 0, 0, 0, time.UTC)

	for i := 0; i < 3; i++ {
		err := s.InsertEvent(parse.Event{
			Time: t0.Add(time.Duration(i) * time.Second), Host: "web-01",
			Program: "sshd", Kind: parse.AuthFail, User: "root",
			IP: "203.0.113.7", Port: 22, Raw: "raw",
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := s.InsertEvent(parse.Event{Time: t0, Host: "web-01", Program: "sshd",
		Kind: parse.AuthFail, User: "x", IP: "198.51.100.9", Raw: "raw"}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertAlert(detect.Alert{Rule: "ssh-brute-force", Key: "203.0.113.7",
		Count: 3, At: t0.Add(2 * time.Second), Last: parse.Event{Raw: "last raw"}}); err != nil {
		t.Fatal(err)
	}

	totals, err := s.Totals()
	if err != nil || totals.Events != 4 || totals.Alerts != 1 {
		t.Fatalf("Totals() = %+v, %v", totals, err)
	}

	alerts, err := s.RecentAlerts(10)
	if err != nil || len(alerts) != 1 {
		t.Fatalf("RecentAlerts() = %v, %v", alerts, err)
	}
	a := alerts[0]
	if a.Rule != "ssh-brute-force" || a.Key != "203.0.113.7" || a.Count != 3 ||
		a.Detail != "last raw" || !a.Time.Equal(t0.Add(2*time.Second)) {
		t.Errorf("alert row = %+v", a)
	}

	top, err := s.TopOffenders(5, t0.Add(-time.Hour))
	if err != nil || len(top) != 2 {
		t.Fatalf("TopOffenders() = %v, %v", top, err)
	}
	if top[0].IP != "203.0.113.7" || top[0].Failures != 3 {
		t.Errorf("top offender = %+v", top[0])
	}
}

func TestSweepRemovesOldRows(t *testing.T) {
	s := open(t)
	t0 := time.Date(2026, 8, 13, 22, 0, 0, 0, time.UTC)

	old := parse.Event{Time: t0.Add(-48 * time.Hour), Kind: parse.AuthFail, IP: "1.2.3.4", Raw: "old"}
	fresh := parse.Event{Time: t0, Kind: parse.AuthFail, IP: "1.2.3.4", Raw: "new"}
	for _, ev := range []parse.Event{old, fresh} {
		if err := s.InsertEvent(ev); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.InsertAlert(detect.Alert{Rule: "r", Key: "k", Count: 1, At: t0.Add(-48 * time.Hour)}); err != nil {
		t.Fatal(err)
	}

	removed, err := s.Sweep(t0.Add(-24 * time.Hour))
	if err != nil || removed != 2 {
		t.Fatalf("Sweep() = %d, %v; want 2 removed", removed, err)
	}
	totals, _ := s.Totals()
	if totals.Events != 1 || totals.Alerts != 0 {
		t.Errorf("after sweep totals = %+v", totals)
	}
}
