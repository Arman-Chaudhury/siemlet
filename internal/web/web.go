// Package web serves the embedded dashboard, a JSON API, health, and metrics.
package web

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"net/http"
	"os"
	"time"

	"github.com/Arman-Chaudhury/siemlet/internal/metrics"
	"github.com/Arman-Chaudhury/siemlet/internal/store"
)

//go:embed dashboard.html.tmpl
var dashboardTmpl string

type Server struct {
	db        *store.Store
	metrics   *metrics.Registry
	ruleCount int
	started   time.Time
	tmpl      *template.Template
}

func New(db *store.Store, reg *metrics.Registry, ruleCount int) *Server {
	tmpl := template.Must(template.New("dashboard").Funcs(template.FuncMap{
		"barWidth": func(n int) int {
			if w := n * 4; w < 240 {
				return w
			}
			return 240
		},
	}).Parse(dashboardTmpl))
	return &Server{
		db:        db,
		metrics:   reg,
		ruleCount: ruleCount,
		started:   time.Now(),
		tmpl:      tmpl,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.dashboard)
	mux.HandleFunc("GET /api/alerts", s.apiAlerts)
	mux.Handle("GET /metrics", s.metrics)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok\n"))
	})
	return mux
}

type dashboardData struct {
	Hostname  string
	Uptime    string
	RuleCount int
	Totals    store.Totals
	Alerts    []store.AlertRow
	Offenders []store.Offender
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	data := dashboardData{RuleCount: s.ruleCount}
	data.Hostname, _ = os.Hostname()
	data.Uptime = time.Since(s.started).Round(time.Second).String()

	var err error
	if data.Totals, err = s.db.Totals(); err == nil {
		if data.Alerts, err = s.db.RecentAlerts(50); err == nil {
			data.Offenders, err = s.db.TopOffenders(10, time.Now().Add(-24*time.Hour))
		}
	}
	if err != nil {
		http.Error(w, "store error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) apiAlerts(w http.ResponseWriter, r *http.Request) {
	alerts, err := s.db.RecentAlerts(200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if alerts == nil {
		alerts = []store.AlertRow{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}
