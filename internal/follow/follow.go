// Package follow tails log files with rotation handling and checkpointing,
// and streams events from journald.
package follow

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"
)

// Follower tails one file, emitting complete lines in order. A checkpoint
// file remembers the byte offset of the last emitted line so restarts
// neither double-ingest nor drop lines. Rotation (a new inode at the same
// path) and in-place truncation both restart from offset 0 of the new
// content. If the file does not exist yet, Run waits for it to appear.
type Follower struct {
	Path       string
	Checkpoint string        // checkpoint file path; "" disables checkpointing
	Poll       time.Duration // idle poll interval; default 500ms
}

type checkpoint struct {
	Offset int64 `json:"offset"`
}

func (f *Follower) pollInterval() time.Duration {
	if f.Poll > 0 {
		return f.Poll
	}
	return 500 * time.Millisecond
}

// Run tails the file until ctx is canceled (returning nil) or an I/O error
// occurs. Each complete line is sent to out with trailing newlines stripped;
// a partial line at EOF is held back until its newline arrives.
func (f *Follower) Run(ctx context.Context, out chan<- string) error {
	var (
		file   *os.File
		r      *bufio.Reader
		offset = f.loadCheckpoint()
		dirty  int
	)
	defer func() {
		if file != nil {
			file.Close()
		}
	}()

	sleep := func() bool {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(f.pollInterval()):
			return true
		}
	}

	open := func() error {
		fi, err := os.Stat(f.Path)
		if err != nil {
			return err
		}
		if offset > fi.Size() { // truncated (or a fresh file) since checkpoint
			offset = 0
		}
		h, err := os.Open(f.Path)
		if err != nil {
			return err
		}
		if _, err := h.Seek(offset, io.SeekStart); err != nil {
			h.Close()
			return err
		}
		file, r = h, bufio.NewReader(h)
		return nil
	}

	for file == nil {
		if err := open(); err == nil {
			break
		}
		if !sleep() {
			return nil
		}
	}

	for {
		line, err := r.ReadString('\n')
		switch {
		case err == nil:
			start := offset
			offset += int64(len(line))
			trimmed := strings.TrimRight(line, "\r\n")
			if trimmed == "" {
				continue
			}
			select {
			case out <- trimmed:
				if dirty++; dirty >= 128 {
					f.saveCheckpoint(offset)
					dirty = 0
				}
			case <-ctx.Done():
				f.saveCheckpoint(start) // unsent line replays on restart
				return nil
			}

		case errors.Is(err, io.EOF):
			if len(line) > 0 {
				// Partial line: rewind so the next pass re-reads it whole.
				if _, serr := file.Seek(offset, io.SeekStart); serr != nil {
					return serr
				}
				r.Reset(file)
			}
			f.saveCheckpoint(offset)
			dirty = 0
			if !sleep() {
				return nil
			}
			fi, statErr := os.Stat(f.Path)
			cur, curErr := file.Stat()
			switch {
			case statErr != nil:
				// Path vanished mid-rotation; keep the old handle and wait
				// for the new file to appear.
			case curErr == nil && !os.SameFile(fi, cur):
				file.Close()
				file, offset = nil, 0
				for file == nil {
					if err := open(); err == nil {
						break
					}
					if !sleep() {
						return nil
					}
				}
			case fi.Size() < offset: // truncated in place
				offset = 0
				if _, err := file.Seek(0, io.SeekStart); err != nil {
					return err
				}
				r.Reset(file)
			}

		default:
			return err
		}
	}
}

// loadCheckpoint returns the saved offset, or 0 when absent or unreadable.
func (f *Follower) loadCheckpoint() int64 {
	if f.Checkpoint == "" {
		return 0
	}
	raw, err := os.ReadFile(f.Checkpoint)
	if err != nil {
		return 0
	}
	var c checkpoint
	if json.Unmarshal(raw, &c) != nil || c.Offset < 0 {
		return 0
	}
	return c.Offset
}

// saveCheckpoint writes the offset atomically (tmp + rename). Checkpointing
// is best-effort: a failed save costs at most re-reading recent lines.
func (f *Follower) saveCheckpoint(offset int64) {
	if f.Checkpoint == "" {
		return
	}
	raw, _ := json.Marshal(checkpoint{Offset: offset})
	tmp := f.Checkpoint + ".tmp"
	if os.WriteFile(tmp, raw, 0o600) == nil {
		os.Rename(tmp, f.Checkpoint)
	}
}
