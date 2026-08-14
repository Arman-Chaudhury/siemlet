package rules

import (
	"strings"
	"testing"
	"time"

	"github.com/Arman-Chaudhury/siemlet/internal/detect"
	"github.com/Arman-Chaudhury/siemlet/internal/parse"
)

func TestDefaultCompilesAllFiveRules(t *testing.T) {
	rs := Default()
	if len(rs) != 5 {
		t.Fatalf("expected 5 stock rules, got %d", len(rs))
	}
	want := []string{"ssh-brute-force", "password-spray", "sudo-after-failures",
		"new-user-created", "off-hours-root"}
	for i, name := range want {
		if rs[i].Name() != name {
			t.Errorf("rule %d = %q, want %q", i, rs[i].Name(), name)
		}
	}
}

func TestDefaultRulesFireEndToEnd(t *testing.T) {
	e := detect.NewEngine(Default()...)
	t0 := time.Date(2026, 8, 13, 3, 0, 0, 0, time.UTC) // 3am: off-hours

	fired := map[string]bool{}
	feed := func(ev parse.Event) {
		for _, a := range e.Feed(ev) {
			fired[a.Rule] = true
		}
	}

	// Brute force: 5 quick failures for one user from one IP.
	for i := 0; i < 5; i++ {
		feed(parse.Event{Kind: parse.AuthFail, IP: "203.0.113.7", User: "root",
			Host: "web-01", Time: t0.Add(time.Duration(i) * time.Second)})
	}
	// Spray: 5 distinct users from another IP, slow enough to dodge brute force.
	for i, u := range []string{"alice", "bob", "carol", "dave", "erin"} {
		feed(parse.Event{Kind: parse.AuthFail, IP: "198.51.100.9", User: u,
			Host: "web-01", Time: t0.Add(time.Duration(i) * 90 * time.Second)})
	}
	// Sudo after failures for one user.
	for i := 0; i < 3; i++ {
		feed(parse.Event{Kind: parse.AuthFail, User: "arman", IP: "192.0.2.4",
			Host: "web-01", Time: t0.Add(10*time.Minute + time.Duration(i)*time.Second)})
	}
	feed(parse.Event{Kind: parse.SudoCommand, User: "arman", Host: "web-01",
		Time: t0.Add(11 * time.Minute)})
	// New user.
	feed(parse.Event{Kind: parse.UserAdded, User: "backdoor", Host: "web-01",
		Time: t0.Add(12 * time.Minute)})
	// Off-hours root login.
	feed(parse.Event{Kind: parse.AuthSuccess, User: "root", IP: "192.0.2.99",
		Host: "web-01", Time: t0.Add(13 * time.Minute)})

	for _, rule := range []string{"ssh-brute-force", "password-spray",
		"sudo-after-failures", "new-user-created", "off-hours-root"} {
		if !fired[rule] {
			t.Errorf("rule %s did not fire; fired: %v", rule, fired)
		}
	}
}

func TestCompileRejectsBadConfigs(t *testing.T) {
	bad := []struct {
		name string
		yaml string
		want string
	}{
		{"empty", "rules: []", "no rules"},
		{"missing name", "rules:\n  - kinds: [auth_fail]\n    threshold: 1", "missing name"},
		{"unknown kind", "rules:\n  - name: x\n    kinds: [nope]\n    threshold: 1", "unknown event kind"},
		{"unknown key", "rules:\n  - name: x\n    kinds: [auth_fail]\n    key: port\n    threshold: 1", "unknown field"},
		{"no window", "rules:\n  - name: x\n    kinds: [auth_fail]\n    threshold: 2", "requires a window"},
		{"bad window", "rules:\n  - name: x\n    kinds: [auth_fail]\n    threshold: 2\n    window: fast", "bad window"},
		{"bad hours", "rules:\n  - name: x\n    kinds: [auth_fail]\n    threshold: 1\n    outside_hours: noonish", "bad hour range"},
		{"duplicate", "rules:\n  - name: x\n    kinds: [auth_fail]\n    threshold: 1\n  - name: x\n    kinds: [auth_fail]\n    threshold: 1", "duplicate"},
		{"one-stage sequence", "rules:\n  - name: x\n    sequence:\n      - kinds: [auth_fail]\n        threshold: 1\n        window: 1m", "exactly 2 stages"},
		{"sequence with kinds", "rules:\n  - name: x\n    kinds: [auth_fail]\n    sequence:\n      - kinds: [auth_fail]\n        threshold: 1\n        window: 1m\n      - kinds: [sudo_command]", "take only"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compile([]byte(tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Compile() err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestLoadReadsExampleConfig(t *testing.T) {
	rs, err := Load("../../configs/rules.example.yaml")
	if err != nil {
		t.Fatalf("example config must stay loadable: %v", err)
	}
	if len(rs) != 5 {
		t.Fatalf("example config has %d rules, want 5", len(rs))
	}
}
