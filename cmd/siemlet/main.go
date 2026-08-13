// siemlet — single-binary SIEM-lite for small Linux fleets.
//
// Implemented: `parse` (structured events + brute-force detection over a file).
// Stubs pending per BUILD_PLAN.md: `watch`, `serve`, `replay`.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Arman-Chaudhury/siemlet/internal/detect"
	"github.com/Arman-Chaudhury/siemlet/internal/parse"
)

const usage = `siemlet — SIEM-lite for small Linux fleets

Usage:
  siemlet parse <logfile>   parse a syslog/auth.log file to JSON events,
                            running the brute-force rule as it goes
  siemlet watch ...         (not implemented — see BUILD_PLAN.md)
  siemlet serve ...         (not implemented — see BUILD_PLAN.md)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "parse":
		if len(os.Args) != 3 {
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		if err := runParse(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "siemlet:", err)
			os.Exit(1)
		}
	case "watch", "serve", "replay":
		fmt.Fprintf(os.Stderr, "siemlet: %q is not implemented yet — see BUILD_PLAN.md\n", os.Args[1])
		os.Exit(1)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func runParse(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	year := time.Now().Year()
	rule := detect.NewBruteForce(5, 2*time.Minute)
	out := json.NewEncoder(os.Stdout)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		ev, err := parse.Line(line, year, time.Local)
		if err != nil {
			fmt.Fprintln(os.Stderr, "siemlet: skipping:", err)
			continue
		}
		if err := out.Encode(ev); err != nil {
			return err
		}
		if alert := rule.Feed(ev); alert != nil {
			fmt.Fprintln(os.Stderr, "ALERT", alert)
		}
	}
	return sc.Err()
}
