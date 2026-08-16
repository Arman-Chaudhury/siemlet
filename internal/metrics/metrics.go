// Package metrics is a minimal counter registry with Prometheus text
// exposition — enough for scraping without pulling in the client library.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

type Registry struct {
	mu       sync.Mutex
	counters map[string]map[string]uint64 // metric name -> label string -> value
}

func New() *Registry {
	return &Registry{counters: make(map[string]map[string]uint64)}
}

// Inc increments a counter by one. Labels are alternating key, value pairs:
// Inc("siemlet_alerts_fired_total", "rule", "ssh-brute-force").
func (r *Registry) Inc(name string, labels ...string) { r.Add(name, 1, labels...) }

func (r *Registry) Add(name string, delta uint64, labels ...string) {
	ls := labelString(labels)
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.counters[name]
	if !ok {
		m = make(map[string]uint64)
		r.counters[name] = m
	}
	m[ls] += delta
}

// Value returns a counter's current value (zero if never incremented).
func (r *Registry) Value(name string, labels ...string) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.counters[name][labelString(labels)]
}

// ServeHTTP writes all counters in Prometheus text exposition format 0.0.4.
func (r *Registry) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make([]string, 0, len(r.counters))
	for name := range r.counters {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(w, "# TYPE %s counter\n", name)
		series := r.counters[name]
		labels := make([]string, 0, len(series))
		for ls := range series {
			labels = append(labels, ls)
		}
		sort.Strings(labels)
		for _, ls := range labels {
			fmt.Fprintf(w, "%s%s %d\n", name, ls, series[ls])
		}
	}
}

func labelString(labels []string) string {
	if len(labels) == 0 {
		return ""
	}
	if len(labels)%2 != 0 {
		labels = append(labels, "")
	}
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i < len(labels); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(labels[i])
		b.WriteString(`="`)
		b.WriteString(escapeLabel(labels[i+1]))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

func escapeLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	return strings.ReplaceAll(v, "\n", `\n`)
}
