package follow

import (
	"bufio"
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
	"time"

	"github.com/Arman-Chaudhury/siemlet/internal/parse"
)

// Journal streams events from journald by running `journalctl -f -o json`.
// journald frames messages itself, so events skip syslog-line parsing and go
// straight through kind classification.
type Journal struct {
	Cmd  string   // command to run; defaults to "journalctl"
	Args []string // extra args, e.g. ["-u", "ssh"]
}

// Run streams events to out until ctx is canceled (returning nil) or the
// journalctl process exits (returning its error, if any).
func (j *Journal) Run(ctx context.Context, out chan<- parse.Event) error {
	name := j.Cmd
	if name == "" {
		name = "journalctl"
	}
	args := append([]string{"-f", "-o", "json", "--no-pager"}, j.Args...)
	cmd := exec.CommandContext(ctx, name, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		ev, ok := journalEvent(sc.Bytes())
		if !ok {
			continue
		}
		select {
		case out <- ev:
		case <-ctx.Done():
		}
	}
	err = cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func journalEvent(raw []byte) (parse.Event, bool) {
	var j struct {
		Message  string `json:"MESSAGE"`
		Host     string `json:"_HOSTNAME"`
		Ident    string `json:"SYSLOG_IDENTIFIER"`
		PID      string `json:"_PID"`
		Realtime string `json:"__REALTIME_TIMESTAMP"` // µs since epoch
	}
	// Binary payloads encode MESSAGE as a byte array; unmarshal fails, skip.
	if json.Unmarshal(raw, &j) != nil || j.Message == "" {
		return parse.Event{}, false
	}
	ev := parse.Event{
		Host:    j.Host,
		Program: j.Ident,
		Kind:    parse.Other,
		Raw:     j.Message,
	}
	if us, err := strconv.ParseInt(j.Realtime, 10, 64); err == nil {
		ev.Time = time.UnixMicro(us)
	} else {
		ev.Time = time.Now()
	}
	ev.PID, _ = strconv.Atoi(j.PID)
	parse.ClassifyMessage(&ev, j.Message)
	return ev, true
}
