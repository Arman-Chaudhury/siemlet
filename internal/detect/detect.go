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

// BruteForce fires when a single source IP produces Threshold or more
// auth-failure events (failed passwords or invalid users) within Window.
// After firing it resets that IP's window, so one attack bursts one alert
// per Threshold failures rather than one per line.
type BruteForce struct {
	Threshold int
	Window    time.Duration

	seen map[string][]time.Time // source IP -> recent failure times, oldest first
}

// NewBruteForce returns a detector with the given threshold and window.
func NewBruteForce(threshold int, window time.Duration) *BruteForce {
	return &BruteForce{
		Threshold: threshold,
		Window:    window,
		seen:      make(map[string][]time.Time),
	}
}

// Feed consumes one event and returns the alert it tripped, if any.
// Events must be fed in (approximately) chronological order, as from a
// log follower.
func (b *BruteForce) Feed(ev parse.Event) *Alert {
	if ev.Kind != parse.AuthFail && ev.Kind != parse.InvalidUser {
		return nil
	}
	if ev.IP == "" {
		return nil
	}
	times := append(b.seen[ev.IP], ev.Time)
	cutoff := ev.Time.Add(-b.Window)
	for len(times) > 0 && times[0].Before(cutoff) {
		times = times[1:]
	}
	if len(times) >= b.Threshold {
		delete(b.seen, ev.IP)
		return &Alert{
			Rule:  "ssh-brute-force",
			Key:   ev.IP,
			Count: len(times),
			At:    ev.Time,
			Last:  ev,
		}
	}
	b.seen[ev.IP] = times
	return nil
}
