package detect

import (
	"testing"
	"time"

	"github.com/Arman-Chaudhury/siemlet/internal/parse"
)

func fail(ip string, at time.Time) parse.Event {
	return parse.Event{Kind: parse.AuthFail, IP: ip, User: "root", Time: at}
}

func TestBruteForceFiresInsideWindow(t *testing.T) {
	d := NewBruteForce(5, 2*time.Minute)
	t0 := time.Date(2026, 8, 13, 22, 0, 0, 0, time.UTC)

	for i := 0; i < 4; i++ {
		if a := d.Feed(fail("203.0.113.7", t0.Add(time.Duration(i)*10*time.Second))); a != nil {
			t.Fatalf("fired early on event %d: %v", i, a)
		}
	}
	a := d.Feed(fail("203.0.113.7", t0.Add(40*time.Second)))
	if a == nil {
		t.Fatal("expected alert on 5th failure inside window")
	}
	if a.Rule != "ssh-brute-force" || a.Key != "203.0.113.7" || a.Count != 5 {
		t.Errorf("alert = %+v", a)
	}
}

func TestBruteForceIgnoresSlowFailures(t *testing.T) {
	d := NewBruteForce(5, 2*time.Minute)
	t0 := time.Date(2026, 8, 13, 22, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		if a := d.Feed(fail("198.51.100.9", t0.Add(time.Duration(i)*3*time.Minute))); a != nil {
			t.Fatalf("fired on spaced-out failures: %v", a)
		}
	}
}

func TestBruteForceKeysPerIP(t *testing.T) {
	d := NewBruteForce(3, time.Minute)
	t0 := time.Date(2026, 8, 13, 22, 0, 0, 0, time.UTC)
	d.Feed(fail("10.0.0.1", t0))
	d.Feed(fail("10.0.0.2", t0.Add(time.Second)))
	d.Feed(fail("10.0.0.1", t0.Add(2*time.Second)))
	if a := d.Feed(fail("10.0.0.2", t0.Add(3*time.Second))); a != nil {
		t.Fatalf("mixed IPs should not fire: %v", a)
	}
	if a := d.Feed(fail("10.0.0.1", t0.Add(4*time.Second))); a == nil {
		t.Fatal("expected alert for 10.0.0.1's third failure")
	}
}

func TestBruteForceResetsAfterFiring(t *testing.T) {
	d := NewBruteForce(2, time.Minute)
	t0 := time.Date(2026, 8, 13, 22, 0, 0, 0, time.UTC)
	d.Feed(fail("10.0.0.5", t0))
	if a := d.Feed(fail("10.0.0.5", t0.Add(time.Second))); a == nil {
		t.Fatal("expected first alert")
	}
	if a := d.Feed(fail("10.0.0.5", t0.Add(2*time.Second))); a != nil {
		t.Fatalf("window should reset after firing, got %v", a)
	}
}

func TestBruteForceIgnoresSuccessesAndMissingIP(t *testing.T) {
	d := NewBruteForce(1, time.Minute)
	t0 := time.Date(2026, 8, 13, 22, 0, 0, 0, time.UTC)
	if a := d.Feed(parse.Event{Kind: parse.AuthSuccess, IP: "10.0.0.1", Time: t0}); a != nil {
		t.Fatalf("success should not count: %v", a)
	}
	if a := d.Feed(parse.Event{Kind: parse.AuthFail, Time: t0}); a != nil {
		t.Fatalf("event without IP should not count: %v", a)
	}
}
