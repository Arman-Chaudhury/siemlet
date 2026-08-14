// siemlet — single-binary SIEM-lite for small Linux fleets.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/Arman-Chaudhury/siemlet/internal/detect"
	"github.com/Arman-Chaudhury/siemlet/internal/follow"
	"github.com/Arman-Chaudhury/siemlet/internal/metrics"
	"github.com/Arman-Chaudhury/siemlet/internal/parse"
	"github.com/Arman-Chaudhury/siemlet/internal/rules"
	"github.com/Arman-Chaudhury/siemlet/internal/sink"
	"github.com/Arman-Chaudhury/siemlet/internal/store"
	"github.com/Arman-Chaudhury/siemlet/internal/web"
)

const usage = `siemlet — SIEM-lite for small Linux fleets

Usage:
  siemlet parse <logfile>              parse one file to JSON events on stdout,
                                       printing alerts from the default rules
  siemlet replay [flags] <logfile>...  run detection rules over historical logs
  siemlet watch  [flags] <logfile>...  follow logs live: detect, store, alert
  siemlet serve  [flags] <logfile>...  watch plus the web dashboard + /metrics

Common flags (replay/watch/serve):
  --rules FILE       YAML rule config (default: built-in rules)
  --db FILE          SQLite database ("" disables storage; watch/serve
                     default siemlet.db, replay default off)
Watch/serve flags:
  --webhook URL      POST alerts to this URL (Slack-compatible payload)
  --journald         also stream events from journalctl
  --checkpoint-dir D per-file offsets live here (default .siemlet)
  --poll DURATION    idle poll interval (default 500ms)
Serve flags:
  --listen ADDR      HTTP address (default 127.0.0.1:8080)
  --retention DUR    delete stored rows older than this (default 720h, 0 keeps all)
`

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "parse":
		err = cmdParse(os.Args[2:])
	case "replay":
		err = cmdReplay(os.Args[2:])
	case "watch":
		err = cmdWatchServe(os.Args[2:], false)
	case "serve":
		err = cmdWatchServe(os.Args[2:], true)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "siemlet:", err)
		os.Exit(1)
	}
}

func loadRules(path string) ([]detect.Rule, error) {
	if path == "" {
		return rules.Default(), nil
	}
	return rules.Load(path)
}

// eachLine feeds every non-empty line of a file to fn.
func eachLine(path string, fn func(string)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if line := sc.Text(); line != "" {
			fn(line)
		}
	}
	return sc.Err()
}

func cmdParse(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: siemlet parse <logfile>")
	}
	engine := detect.NewEngine(rules.Default()...)
	year := time.Now().Year()
	out := json.NewEncoder(os.Stdout)

	return eachLine(args[0], func(line string) {
		ev, err := parse.Line(line, year, time.Local)
		if err != nil {
			fmt.Fprintln(os.Stderr, "siemlet: skipping:", err)
			return
		}
		out.Encode(ev)
		for _, a := range engine.Feed(ev) {
			fmt.Fprintln(os.Stderr, "ALERT", a)
		}
	})
}

func cmdReplay(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	rulesPath := fs.String("rules", "", "YAML rule config")
	dbPath := fs.String("db", "", "SQLite database to record into")
	fs.Parse(args)
	if fs.NArg() == 0 {
		return errors.New("usage: siemlet replay [flags] <logfile>...")
	}

	rs, err := loadRules(*rulesPath)
	if err != nil {
		return err
	}
	engine := detect.NewEngine(rs...)

	var db *store.Store
	if *dbPath != "" {
		if db, err = store.Open(*dbPath); err != nil {
			return err
		}
		defer db.Close()
	}

	year := time.Now().Year()
	var events, alerts, skipped int
	for _, path := range fs.Args() {
		err := eachLine(path, func(line string) {
			ev, err := parse.Line(line, year, time.Local)
			if err != nil {
				skipped++
				return
			}
			events++
			if db != nil && ev.Kind != parse.Other {
				db.InsertEvent(ev)
			}
			for _, a := range engine.Feed(ev) {
				alerts++
				fmt.Println("ALERT", a)
				if db != nil {
					db.InsertAlert(a)
				}
			}
		})
		if err != nil {
			return err
		}
	}
	fmt.Printf("replayed %d events from %d file(s): %d alert(s), %d unparsed line(s)\n",
		events, fs.NArg(), alerts, skipped)
	return nil
}

func cmdWatchServe(args []string, serve bool) error {
	name := "watch"
	if serve {
		name = "serve"
	}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	rulesPath := fs.String("rules", "", "YAML rule config")
	dbPath := fs.String("db", "siemlet.db", "SQLite database ('' disables)")
	webhookURL := fs.String("webhook", "", "webhook URL for alerts")
	journald := fs.Bool("journald", false, "also stream from journalctl")
	ckptDir := fs.String("checkpoint-dir", ".siemlet", "checkpoint directory")
	poll := fs.Duration("poll", 500*time.Millisecond, "idle poll interval")
	listen := fs.String("listen", "127.0.0.1:8080", "HTTP listen address (serve)")
	retention := fs.Duration("retention", 720*time.Hour, "row retention (serve; 0 keeps all)")
	fs.Parse(args)

	if fs.NArg() == 0 && !*journald {
		return fmt.Errorf("usage: siemlet %s [flags] <logfile>... (and/or --journald)", name)
	}
	if serve && *dbPath == "" {
		return errors.New("serve needs --db (the dashboard reads from it)")
	}

	rs, err := loadRules(*rulesPath)
	if err != nil {
		return err
	}
	engine := detect.NewEngine(rs...)
	reg := metrics.New()

	var db *store.Store
	if *dbPath != "" {
		if db, err = store.Open(*dbPath); err != nil {
			return err
		}
		defer db.Close()
	}

	var webhook *sink.Webhook
	if *webhookURL != "" {
		webhook = &sink.Webhook{URL: *webhookURL, OnDrop: func(reason string) {
			reg.Inc("siemlet_alerts_dropped_total", "reason", reason)
		}}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	events := make(chan parse.Event, 256)
	var wg sync.WaitGroup

	// File followers feed raw lines; one converter goroutine parses them.
	if fs.NArg() > 0 {
		if err := os.MkdirAll(*ckptDir, 0o700); err != nil {
			return err
		}
		lines := make(chan string, 256)
		for _, path := range fs.Args() {
			f := &follow.Follower{
				Path:       path,
				Checkpoint: filepath.Join(*ckptDir, filepath.Base(path)+".ckpt"),
				Poll:       *poll,
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := f.Run(ctx, lines); err != nil {
					log.Printf("follower %s: %v", f.Path, err)
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			year := time.Now().Year()
			for {
				select {
				case <-ctx.Done():
					return
				case line := <-lines:
					ev, err := parse.Line(line, year, time.Local)
					if err != nil {
						reg.Inc("siemlet_parse_errors_total")
						continue
					}
					select {
					case events <- ev:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	if *journald {
		j := &follow.Journal{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := j.Run(ctx, events); err != nil {
				log.Printf("journald: %v", err)
			}
		}()
	}

	if serve {
		srv := &http.Server{Addr: *listen, Handler: web.New(db, reg, engine.Len()).Handler()}
		ln, err := net.Listen("tcp", *listen)
		if err != nil {
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("http: %v", err)
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			srv.Shutdown(shutdownCtx)
		}()
		log.Printf("dashboard on http://%s", *listen)

		if *retention > 0 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				tick := time.NewTicker(time.Hour)
				defer tick.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-tick.C:
						if n, err := db.Sweep(time.Now().Add(-*retention)); err != nil {
							log.Printf("retention sweep: %v", err)
						} else if n > 0 {
							log.Printf("retention sweep removed %d rows", n)
						}
					}
				}
			}()
		}
	}

	log.Printf("watching %d file(s), journald=%v, %d rules, db=%s",
		fs.NArg(), *journald, engine.Len(), orNone(*dbPath))

	// Single consumer: rules aren't goroutine-safe, and one writer keeps
	// SQLite happy.
	for {
		select {
		case <-ctx.Done():
			stop()
			wg.Wait()
			return nil
		case ev := <-events:
			reg.Inc("siemlet_events_ingested_total")
			if db != nil && ev.Kind != parse.Other {
				if err := db.InsertEvent(ev); err != nil {
					log.Printf("store event: %v", err)
				}
			}
			for _, a := range engine.Feed(ev) {
				log.Println("ALERT", a)
				reg.Inc("siemlet_alerts_fired_total", "rule", a.Rule)
				if db != nil {
					if err := db.InsertAlert(a); err != nil {
						log.Printf("store alert: %v", err)
					}
				}
				if webhook != nil {
					if sent, err := webhook.Send(a); err != nil {
						log.Printf("webhook: %v", err)
						reg.Inc("siemlet_webhook_errors_total")
					} else if sent {
						reg.Inc("siemlet_alerts_sent_total")
					}
				}
			}
		}
	}
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
