// Package store persists events and alerts in a single SQLite file.
package store

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite" // cgo-free driver, keeps the binary static

	"github.com/Arman-Chaudhury/siemlet/internal/detect"
	"github.com/Arman-Chaudhury/siemlet/internal/parse"
)

const schema = `
CREATE TABLE IF NOT EXISTS events (
  id      INTEGER PRIMARY KEY,
  time    TEXT    NOT NULL,
  host    TEXT    NOT NULL DEFAULT '',
  program TEXT    NOT NULL DEFAULT '',
  kind    TEXT    NOT NULL,
  user    TEXT    NOT NULL DEFAULT '',
  ip      TEXT    NOT NULL DEFAULT '',
  port    INTEGER NOT NULL DEFAULT 0,
  detail  TEXT    NOT NULL DEFAULT '',
  raw     TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS events_time    ON events(time);
CREATE INDEX IF NOT EXISTS events_ip_kind ON events(ip, kind);

CREATE TABLE IF NOT EXISTS alerts (
  id     INTEGER PRIMARY KEY,
  time   TEXT    NOT NULL,
  rule   TEXT    NOT NULL,
  key    TEXT    NOT NULL,
  count  INTEGER NOT NULL,
  detail TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS alerts_time ON alerts(time);
`

type Store struct {
	db *sql.DB
}

// Open creates or opens the SQLite file and applies the schema.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite",
		"file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	// One writer connection sidesteps SQLITE_BUSY between goroutines.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func (s *Store) InsertEvent(ev parse.Event) error {
	_, err := s.db.Exec(
		`INSERT INTO events (time, host, program, kind, user, ip, port, detail, raw)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ts(ev.Time), ev.Host, ev.Program, string(ev.Kind), ev.User, ev.IP, ev.Port, ev.Detail, ev.Raw)
	return err
}

func (s *Store) InsertAlert(a detect.Alert) error {
	_, err := s.db.Exec(
		`INSERT INTO alerts (time, rule, key, count, detail) VALUES (?, ?, ?, ?, ?)`,
		ts(a.At), a.Rule, a.Key, a.Count, a.Last.Raw)
	return err
}

type AlertRow struct {
	Time   time.Time `json:"time"`
	Rule   string    `json:"rule"`
	Key    string    `json:"key"`
	Count  int       `json:"count"`
	Detail string    `json:"detail"`
}

// RecentAlerts returns the newest alerts first.
func (s *Store) RecentAlerts(limit int) ([]AlertRow, error) {
	rows, err := s.db.Query(
		`SELECT time, rule, key, count, detail FROM alerts ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertRow
	for rows.Next() {
		var r AlertRow
		var when string
		if err := rows.Scan(&when, &r.Rule, &r.Key, &r.Count, &r.Detail); err != nil {
			return nil, err
		}
		r.Time, _ = time.Parse(time.RFC3339Nano, when)
		out = append(out, r)
	}
	return out, rows.Err()
}

type Offender struct {
	IP       string `json:"ip"`
	Failures int    `json:"failures"`
}

// TopOffenders ranks source IPs by auth failures since the given time.
func (s *Store) TopOffenders(limit int, since time.Time) ([]Offender, error) {
	rows, err := s.db.Query(
		`SELECT ip, COUNT(*) AS n FROM events
		 WHERE kind IN ('auth_fail', 'invalid_user') AND ip != '' AND time >= ?
		 GROUP BY ip ORDER BY n DESC, ip LIMIT ?`, ts(since), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Offender
	for rows.Next() {
		var o Offender
		if err := rows.Scan(&o.IP, &o.Failures); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

type Totals struct {
	Events int64 `json:"events"`
	Alerts int64 `json:"alerts"`
}

func (s *Store) Totals() (Totals, error) {
	var t Totals
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&t.Events); err != nil {
		return t, err
	}
	err := s.db.QueryRow(`SELECT COUNT(*) FROM alerts`).Scan(&t.Alerts)
	return t, err
}

// Sweep deletes events and alerts older than the given time and reports how
// many rows were removed.
func (s *Store) Sweep(olderThan time.Time) (int64, error) {
	var removed int64
	for _, table := range []string{"events", "alerts"} {
		res, err := s.db.Exec(`DELETE FROM `+table+` WHERE time < ?`, ts(olderThan))
		if err != nil {
			return removed, err
		}
		n, _ := res.RowsAffected()
		removed += n
	}
	return removed, nil
}
