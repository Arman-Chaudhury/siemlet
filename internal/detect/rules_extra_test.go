package detect

import (
	"testing"
	"time"

	"github.com/Arman-Chaudhury/siemlet/internal/parse"
)

func at(h, m int) time.Time {
	return time.Date(2026, 8, 13, h, m, 0, 0, time.UTC)
}

func TestWindowRuleDistinctCountsUsers(t *testing.T) {
	spray := &WindowRule{
		RuleName:  "password-spray",
		Kinds:     map[parse.Kind]bool{parse.AuthFail: true},
		Key:       FieldIP,
		Distinct:  FieldUser,
		Threshold: 3,
		Window:    10 * time.Minute,
	}
	t0 := at(12, 0)
	// Same user failing repeatedly is brute force, not spray.
	for i := 0; i < 5; i++ {
		ev := parse.Event{Kind: parse.AuthFail, IP: "203.0.113.9", User: "root",
			Time: t0.Add(time.Duration(i) * time.Second)}
		if a := spray.Feed(ev); a != nil {
			t.Fatalf("same-user failures should not fire spray: %v", a)
		}
	}
	// Three distinct users from one IP fires exactly on the third user.
	var got *Alert
	for i, u := range []string{"alice", "bob", "carol"} {
		a := spray.Feed(parse.Event{Kind: parse.AuthFail, IP: "198.51.100.4", User: u,
			Time: t0.Add(time.Minute + time.Duration(i)*time.Second)})
		if a != nil {
			if got != nil {
				t.Fatalf("spray fired twice: %v then %v", got, a)
			}
			if u != "carol" {
				t.Fatalf("spray fired early on %s: %v", u, a)
			}
			got = a
		}
	}
	if got == nil || got.Count != 3 {
		t.Fatalf("expected spray alert with 3 distinct users, got %v", got)
	}
}

func TestWindowRuleUserFilterAndOutsideHours(t *testing.T) {
	hr, err := ParseHourRange("08:00-20:00")
	if err != nil {
		t.Fatal(err)
	}
	rule := &WindowRule{
		RuleName:  "off-hours-root",
		Kinds:     map[parse.Kind]bool{parse.AuthSuccess: true},
		Key:       FieldHost,
		Threshold: 1,
		Window:    time.Second,
		User:      "root",
		Outside:   &hr,
	}
	daytime := parse.Event{Kind: parse.AuthSuccess, User: "root", Host: "web-01", Time: at(12, 0)}
	if a := rule.Feed(daytime); a != nil {
		t.Fatalf("daytime root login should not fire: %v", a)
	}
	otherUser := parse.Event{Kind: parse.AuthSuccess, User: "arman", Host: "web-01", Time: at(3, 0)}
	if a := rule.Feed(otherUser); a != nil {
		t.Fatalf("non-root login should not fire: %v", a)
	}
	night := parse.Event{Kind: parse.AuthSuccess, User: "root", Host: "web-01", Time: at(3, 0)}
	if a := rule.Feed(night); a == nil {
		t.Fatal("3am root login should fire")
	}
}

func TestHourRangeWrapsMidnight(t *testing.T) {
	hr, err := ParseHourRange("22:00-06:00")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		h, m int
		want bool
	}{{23, 0, true}, {2, 30, true}, {12, 0, false}, {6, 0, false}, {22, 0, true}} {
		if got := hr.Contains(at(tc.h, tc.m)); got != tc.want {
			t.Errorf("Contains(%02d:%02d) = %v, want %v", tc.h, tc.m, got, tc.want)
		}
	}
}

func TestSequenceRuleSudoAfterFailures(t *testing.T) {
	rule := &SequenceRule{
		RuleName:     "sudo-after-failures",
		PreKinds:     map[parse.Kind]bool{parse.AuthFail: true},
		PreThreshold: 3,
		Window:       10 * time.Minute,
		TriggerKinds: map[parse.Kind]bool{parse.SudoCommand: true},
		Key:          FieldUser,
	}
	t0 := at(14, 0)
	sudo := func(user string, tm time.Time) parse.Event {
		return parse.Event{Kind: parse.SudoCommand, User: user, Time: tm}
	}
	failEv := func(user string, tm time.Time) parse.Event {
		return parse.Event{Kind: parse.AuthFail, User: user, IP: "203.0.113.5", Time: tm}
	}

	// sudo with no prior failures: quiet.
	if a := rule.Feed(sudo("arman", t0)); a != nil {
		t.Fatalf("clean sudo fired: %v", a)
	}
	// Two failures then sudo: still under threshold.
	rule.Feed(failEv("arman", t0.Add(1*time.Minute)))
	rule.Feed(failEv("arman", t0.Add(2*time.Minute)))
	if a := rule.Feed(sudo("arman", t0.Add(3*time.Minute))); a != nil {
		t.Fatalf("2 failures then sudo fired: %v", a)
	}
	// A third failure, then sudo: fires (failures still inside 10m window).
	rule.Feed(failEv("arman", t0.Add(4*time.Minute)))
	a := rule.Feed(sudo("arman", t0.Add(5*time.Minute)))
	if a == nil || a.Key != "arman" || a.Count != 3 {
		t.Fatalf("expected sudo-after-failures for arman with 3 precursors, got %v", a)
	}
	// State reset after firing.
	if a := rule.Feed(sudo("arman", t0.Add(6*time.Minute))); a != nil {
		t.Fatalf("fired again without new failures: %v", a)
	}
	// Failures aged out of the window don't count.
	rule.Feed(failEv("bob", t0))
	rule.Feed(failEv("bob", t0.Add(time.Minute)))
	rule.Feed(failEv("bob", t0.Add(2*time.Minute)))
	if a := rule.Feed(sudo("bob", t0.Add(30*time.Minute))); a != nil {
		t.Fatalf("stale failures fired: %v", a)
	}
}

func TestEngineFansOut(t *testing.T) {
	e := NewEngine(
		NewBruteForce(2, time.Minute),
		&WindowRule{
			RuleName:  "new-user-created",
			Kinds:     map[parse.Kind]bool{parse.UserAdded: true},
			Key:       FieldHost,
			Threshold: 1,
			Window:    time.Second,
		},
	)
	t0 := at(9, 0)
	if got := e.Feed(parse.Event{Kind: parse.UserAdded, User: "eve", Host: "web-01", Time: t0}); len(got) != 1 || got[0].Rule != "new-user-created" {
		t.Fatalf("expected new-user-created alert, got %v", got)
	}
	e.Feed(parse.Event{Kind: parse.AuthFail, IP: "10.0.0.1", Host: "web-01", Time: t0})
	got := e.Feed(parse.Event{Kind: parse.AuthFail, IP: "10.0.0.1", Host: "web-01", Time: t0.Add(time.Second)})
	if len(got) != 1 || got[0].Rule != "ssh-brute-force" {
		t.Fatalf("expected ssh-brute-force alert, got %v", got)
	}
}
