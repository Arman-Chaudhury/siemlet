// Package parse turns raw Linux auth.log / syslog lines into structured events.
package parse

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Kind classifies what an auth log line means.
type Kind string

const (
	AuthFail    Kind = "auth_fail"    // failed password / PAM auth failure
	AuthSuccess Kind = "auth_success" // accepted password or publickey
	InvalidUser Kind = "invalid_user" // attempt against a nonexistent user
	SudoCommand Kind = "sudo_command" // sudo command execution
	UserAdded   Kind = "user_added"   // useradd/adduser created an account
	Other       Kind = "other"        // recognized syslog line, unclassified
)

// Event is one structured auth event.
type Event struct {
	Time    time.Time `json:"time"`
	Host    string    `json:"host"`
	Program string    `json:"program"`
	PID     int       `json:"pid,omitempty"`
	Kind    Kind      `json:"kind"`
	User    string    `json:"user,omitempty"`
	IP      string    `json:"ip,omitempty"`
	Port    int       `json:"port,omitempty"`
	Detail  string    `json:"detail,omitempty"`
	Raw     string    `json:"raw"`
}

// syslogPrefix matches the classic "Aug 13 22:41:07 host prog[pid]: msg" framing.
var syslogPrefix = regexp.MustCompile(
	`^([A-Z][a-z]{2}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2}) (\S+) ([\w./-]+)(?:\[(\d+)\])?: (.*)$`)

var (
	reFailed = regexp.MustCompile(
		`^Failed (?:password|publickey) for (invalid user )?(\S+) from (\S+) port (\d+)`)
	reAccepted = regexp.MustCompile(
		`^Accepted (?:password|publickey|keyboard-interactive/pam) for (\S+) from (\S+) port (\d+)`)
	rePAMFail = regexp.MustCompile(
		`authentication failure;.* rhost=(\S*)(?:\s+user=(\S+))?`)
	reInvalid = regexp.MustCompile(
		`^Invalid user (\S+) from (\S+)(?: port (\d+))?`)
	reSudo = regexp.MustCompile(
		`^\s*(\S+) : .*COMMAND=(.*)$`)
	reUserAdd = regexp.MustCompile(
		`^new user: name=([^,]+)`)
)

// Line parses one syslog line. The year is not present in classic syslog
// timestamps, so callers supply it (typically time.Now().Year()).
// Unrecognized message bodies still return an event with Kind == Other;
// lines that are not syslog-framed at all return an error.
func Line(line string, year int, loc *time.Location) (Event, error) {
	m := syslogPrefix.FindStringSubmatch(line)
	if m == nil {
		return Event{}, fmt.Errorf("not a syslog-framed line: %q", line)
	}
	ts, err := time.ParseInLocation("Jan 2 15:04:05", squeezeSpaces(m[1]), loc)
	if err != nil {
		return Event{}, fmt.Errorf("bad timestamp %q: %w", m[1], err)
	}
	ev := Event{
		Time:    ts.AddDate(year, 0, 0),
		Host:    m[2],
		Program: m[3],
		Kind:    Other,
		Raw:     line,
	}
	if m[4] != "" {
		ev.PID, _ = strconv.Atoi(m[4])
	}
	classify(&ev, m[5])
	return ev, nil
}

func classify(ev *Event, msg string) {
	switch {
	case matchInto(reFailed, msg, func(g []string) {
		ev.Kind = AuthFail
		if g[1] != "" {
			ev.Kind = InvalidUser
		}
		ev.User, ev.IP = g[2], g[3]
		ev.Port, _ = strconv.Atoi(g[4])
	}):
	case matchInto(reAccepted, msg, func(g []string) {
		ev.Kind = AuthSuccess
		ev.User, ev.IP = g[1], g[2]
		ev.Port, _ = strconv.Atoi(g[3])
	}):
	case matchInto(reInvalid, msg, func(g []string) {
		ev.Kind = InvalidUser
		ev.User, ev.IP = g[1], g[2]
		if g[3] != "" {
			ev.Port, _ = strconv.Atoi(g[3])
		}
	}):
	case matchInto(rePAMFail, msg, func(g []string) {
		ev.Kind = AuthFail
		ev.IP, ev.User = g[1], g[2]
	}):
	case ev.Program == "sudo" && matchInto(reSudo, msg, func(g []string) {
		ev.Kind = SudoCommand
		ev.User, ev.Detail = g[1], g[2]
	}):
	case matchInto(reUserAdd, msg, func(g []string) {
		ev.Kind = UserAdded
		ev.User = g[1]
	}):
	}
}

// ClassifyMessage classifies a bare message body (no syslog framing) into ev.
// Sources that provide their own framing (e.g. journald) fill in Time, Host,
// Program, and PID themselves and use this for the message body only.
func ClassifyMessage(ev *Event, msg string) { classify(ev, msg) }

// matchInto runs re against msg and, on a hit, hands the submatches to fn.
func matchInto(re *regexp.Regexp, msg string, fn func([]string)) bool {
	g := re.FindStringSubmatch(msg)
	if g == nil {
		return false
	}
	fn(g)
	return true
}

// squeezeSpaces collapses the double space in day-of-month < 10 ("Aug  3").
func squeezeSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
