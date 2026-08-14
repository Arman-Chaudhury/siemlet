// Package detect implements sliding-window detection rules over parsed events.
package detect

import (
	"fmt"
	"time"

	"github.com/Arman-Chaudhury/siemlet/internal/parse"
)

// Alert is one fired detection.
type Alert struct {
	Rule  string      `json:"rule"`
	Key   string      `json:"key"`   // the offending key, e.g. source IP
	Count int         `json:"count"` // matching events inside the window
	At    time.Time   `json:"at"`    // time of the event that tripped the rule
	Last  parse.Event `json:"last"`  // the tripping event
}

func (a Alert) String() string {
	return fmt.Sprintf("[%s] %s: %d events within window (last at %s)",
		a.Rule, a.Key, a.Count, a.At.Format(time.RFC3339))
}

// Rule consumes events in roughly chronological order and occasionally fires.
// Rules are not safe for concurrent use; feed them from one goroutine.
type Rule interface {
	Name() string
	Feed(parse.Event) *Alert
}

// Engine fans one event stream across a set of rules.
type Engine struct {
	rules []Rule
}

func NewEngine(rules ...Rule) *Engine { return &Engine{rules: rules} }

func (e *Engine) Len() int { return len(e.rules) }

func (e *Engine) Feed(ev parse.Event) []Alert {
	var out []Alert
	for _, r := range e.rules {
		if a := r.Feed(ev); a != nil {
			out = append(out, *a)
		}
	}
	return out
}

// Field names an Event attribute rules can key or count by.
type Field string

const (
	FieldNone Field = ""
	FieldIP   Field = "ip"
	FieldUser Field = "user"
	FieldHost Field = "host"
)

func (f Field) of(ev parse.Event) string {
	switch f {
	case FieldIP:
		return ev.IP
	case FieldUser:
		return ev.User
	case FieldHost:
		return ev.Host
	}
	return ""
}

// HourRange is a daily interval like 08:00-20:00 in the event's location.
// Start == End is rejected at parse time; Start > End wraps past midnight.
type HourRange struct {
	startMin, endMin int
}

func ParseHourRange(s string) (HourRange, error) {
	var h1, m1, h2, m2 int
	if _, err := fmt.Sscanf(s, "%d:%d-%d:%d", &h1, &m1, &h2, &m2); err != nil {
		return HourRange{}, fmt.Errorf("bad hour range %q (want HH:MM-HH:MM): %w", s, err)
	}
	for _, v := range [][2]int{{h1, 23}, {m1, 59}, {h2, 23}, {m2, 59}} {
		if v[0] < 0 || v[0] > v[1] {
			return HourRange{}, fmt.Errorf("bad hour range %q: out of range", s)
		}
	}
	r := HourRange{h1*60 + m1, h2*60 + m2}
	if r.startMin == r.endMin {
		return HourRange{}, fmt.Errorf("bad hour range %q: empty range", s)
	}
	return r, nil
}

func (h HourRange) Contains(t time.Time) bool {
	m := t.Hour()*60 + t.Minute()
	if h.startMin < h.endMin {
		return m >= h.startMin && m < h.endMin
	}
	return m >= h.startMin || m < h.endMin // wraps past midnight
}

// sweepEvery bounds detector memory: every N feeds, keys whose entries all
// fell out of the window are dropped, so one-off IPs don't accumulate forever.
const sweepEvery = 4096

type entry struct {
	t        time.Time
	distinct string
}

// WindowRule fires when Threshold matching events (or, with Distinct set,
// events carrying that many distinct values of the Distinct field) share the
// same Key value within Window. After firing, the key's window resets, so a
// sustained attack alerts once per Threshold events rather than once per line.
type WindowRule struct {
	RuleName  string
	Kinds     map[parse.Kind]bool
	Key       Field
	Distinct  Field // when set, count distinct values instead of raw events
	Threshold int
	Window    time.Duration
	User      string     // when set, only events for this exact user match
	Outside   *HourRange // when set, only events outside these hours match

	feeds int
	seen  map[string][]entry
}

func (w *WindowRule) Name() string { return w.RuleName }

func (w *WindowRule) Feed(ev parse.Event) *Alert {
	if !w.Kinds[ev.Kind] {
		return nil
	}
	if w.User != "" && ev.User != w.User {
		return nil
	}
	if w.Outside != nil && w.Outside.Contains(ev.Time) {
		return nil
	}
	key := w.Key.of(ev)
	if key == "" {
		return nil
	}
	if w.seen == nil {
		w.seen = make(map[string][]entry)
	}
	w.sweep(ev.Time)

	cutoff := ev.Time.Add(-w.Window)
	es := pruneEntries(append(w.seen[key], entry{ev.Time, w.Distinct.of(ev)}), cutoff)
	count := len(es)
	if w.Distinct != FieldNone {
		set := make(map[string]struct{}, len(es))
		for _, e := range es {
			if e.distinct != "" {
				set[e.distinct] = struct{}{}
			}
		}
		count = len(set)
	}
	if count >= w.Threshold {
		delete(w.seen, key)
		return &Alert{Rule: w.RuleName, Key: key, Count: count, At: ev.Time, Last: ev}
	}
	w.seen[key] = es
	return nil
}

func (w *WindowRule) sweep(now time.Time) {
	if w.feeds++; w.feeds < sweepEvery {
		return
	}
	w.feeds = 0
	cutoff := now.Add(-w.Window)
	for k, es := range w.seen {
		if es = pruneEntries(es, cutoff); len(es) == 0 {
			delete(w.seen, k)
		} else {
			w.seen[k] = es
		}
	}
}

// SequenceRule fires when a trigger event follows PreThreshold or more
// precursor events with the same Key value inside Window — e.g. a sudo
// command shortly after repeated auth failures for the same user.
type SequenceRule struct {
	RuleName     string
	PreKinds     map[parse.Kind]bool
	PreThreshold int
	Window       time.Duration
	TriggerKinds map[parse.Kind]bool
	Key          Field

	feeds int
	seen  map[string][]time.Time
}

func (s *SequenceRule) Name() string { return s.RuleName }

func (s *SequenceRule) Feed(ev parse.Event) *Alert {
	key := s.Key.of(ev)
	if key == "" {
		return nil
	}
	if s.seen == nil {
		s.seen = make(map[string][]time.Time)
	}
	s.sweep(ev.Time)

	cutoff := ev.Time.Add(-s.Window)
	if s.PreKinds[ev.Kind] {
		s.seen[key] = pruneTimes(append(s.seen[key], ev.Time), cutoff)
		return nil
	}
	if !s.TriggerKinds[ev.Kind] {
		return nil
	}
	ts := pruneTimes(s.seen[key], cutoff)
	if len(ts) >= s.PreThreshold {
		delete(s.seen, key)
		return &Alert{Rule: s.RuleName, Key: key, Count: len(ts), At: ev.Time, Last: ev}
	}
	s.seen[key] = ts
	return nil
}

func (s *SequenceRule) sweep(now time.Time) {
	if s.feeds++; s.feeds < sweepEvery {
		return
	}
	s.feeds = 0
	cutoff := now.Add(-s.Window)
	for k, ts := range s.seen {
		if ts = pruneTimes(ts, cutoff); len(ts) == 0 {
			delete(s.seen, k)
		} else {
			s.seen[k] = ts
		}
	}
}

// NewBruteForce returns the stock ssh-brute-force rule: threshold auth
// failures (failed passwords or invalid users) from one source IP within
// window.
func NewBruteForce(threshold int, window time.Duration) *WindowRule {
	return &WindowRule{
		RuleName:  "ssh-brute-force",
		Kinds:     map[parse.Kind]bool{parse.AuthFail: true, parse.InvalidUser: true},
		Key:       FieldIP,
		Threshold: threshold,
		Window:    window,
	}
}

func pruneEntries(es []entry, cutoff time.Time) []entry {
	for len(es) > 0 && es[0].t.Before(cutoff) {
		es = es[1:]
	}
	return es
}

func pruneTimes(ts []time.Time, cutoff time.Time) []time.Time {
	for len(ts) > 0 && ts[0].Before(cutoff) {
		ts = ts[1:]
	}
	return ts
}
