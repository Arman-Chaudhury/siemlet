package follow

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Arman-Chaudhury/siemlet/internal/parse"
)

const testPoll = 5 * time.Millisecond

func startFollower(t *testing.T, f *Follower) (<-chan string, context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan string, 64)
	done := make(chan error, 1)
	go func() { done <- f.Run(ctx, out) }()
	t.Cleanup(cancel)
	return out, cancel, done
}

func expectLine(t *testing.T, out <-chan string, want string) {
	t.Helper()
	select {
	case got := <-out:
		if got != want {
			t.Fatalf("got line %q, want %q", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for line %q", want)
	}
}

func expectQuiet(t *testing.T, out <-chan string) {
	t.Helper()
	select {
	case got := <-out:
		t.Fatalf("unexpected line %q", got)
	case <-time.After(20 * testPoll):
	}
}

func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func TestFollowerTailsAppends(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	appendLine(t, path, "one")

	out, _, _ := startFollower(t, &Follower{Path: path, Poll: testPoll})
	expectLine(t, out, "one")
	appendLine(t, path, "two")
	expectLine(t, out, "two")
}

func TestFollowerHoldsPartialLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(path, []byte("partial"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _, _ := startFollower(t, &Follower{Path: path, Poll: testPoll})
	expectQuiet(t, out)
	appendLine(t, path, " line done") // completes "partial line done\n"
	expectLine(t, out, "partial line done")
}

func TestFollowerHandlesRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	appendLine(t, path, "old-1")

	out, _, _ := startFollower(t, &Follower{Path: path, Poll: testPoll})
	expectLine(t, out, "old-1")

	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendLine(t, path, "new-1")
	expectLine(t, out, "new-1")
	appendLine(t, path, "new-2")
	expectLine(t, out, "new-2")
}

func TestFollowerHandlesTruncation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	appendLine(t, path, "before-1")
	appendLine(t, path, "before-2")

	out, _, _ := startFollower(t, &Follower{Path: path, Poll: testPoll})
	expectLine(t, out, "before-1")
	expectLine(t, out, "before-2")

	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	// Give the follower a beat to notice the shrink before new writes grow
	// the file past the old offset again.
	time.Sleep(10 * testPoll)
	appendLine(t, path, "after-1")
	expectLine(t, out, "after-1")
}

func TestFollowerWaitsForFileToAppear(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")

	out, _, _ := startFollower(t, &Follower{Path: path, Poll: testPoll})
	expectQuiet(t, out)
	appendLine(t, path, "born")
	expectLine(t, out, "born")
}

func TestFollowerCheckpointResumesWithoutDuplicates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	ckpt := filepath.Join(dir, "auth.log.ckpt")
	appendLine(t, path, "one")
	appendLine(t, path, "two")

	out, cancel, done := startFollower(t, &Follower{Path: path, Checkpoint: ckpt, Poll: testPoll})
	expectLine(t, out, "one")
	expectLine(t, out, "two")
	// Let an idle poll pass so the checkpoint covers both lines.
	time.Sleep(5 * testPoll)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run() = %v", err)
	}

	appendLine(t, path, "three")
	out2, cancel2, done2 := startFollower(t, &Follower{Path: path, Checkpoint: ckpt, Poll: testPoll})
	expectLine(t, out2, "three")
	expectQuiet(t, out2)
	cancel2()
	if err := <-done2; err != nil {
		t.Fatalf("second Run() = %v", err)
	}
}

func TestJournalStreamsEvents(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "journalctl")
	script := `#!/bin/sh
echo '{"MESSAGE":"Failed password for root from 203.0.113.7 port 22 ssh2","_HOSTNAME":"web-01","SYSLOG_IDENTIFIER":"sshd","_PID":"77","__REALTIME_TIMESTAMP":"1755100000000000"}'
echo 'not json'
echo '{"MESSAGE":"Accepted publickey for arman from 198.51.100.3 port 22 ssh2","_HOSTNAME":"web-01","SYSLOG_IDENTIFIER":"sshd","_PID":"78","__REALTIME_TIMESTAMP":"1755100001000000"}'
`
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	out := make(chan parse.Event, 8)
	j := &Journal{Cmd: fake}
	if err := j.Run(context.Background(), out); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	close(out)

	var got []parse.Event
	for ev := range out {
		got = append(got, ev)
	}
	if len(got) != 2 {
		t.Fatalf("got %d events, want 2 (non-JSON line skipped): %+v", len(got), got)
	}
	if got[0].Kind != parse.AuthFail || got[0].IP != "203.0.113.7" ||
		got[0].Host != "web-01" || got[0].PID != 77 {
		t.Errorf("first event = %+v", got[0])
	}
	if got[0].Time.UnixMicro() != 1755100000000000 {
		t.Errorf("first event time = %v", got[0].Time)
	}
	if got[1].Kind != parse.AuthSuccess || got[1].User != "arman" {
		t.Errorf("second event = %+v", got[1])
	}
}
