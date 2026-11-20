package log

import (
	"strings"
	"sync"
	"time"
)

// Line is one parsed log record kept in a Buffer for the local console.
type Line struct {
	Seq   int64  `json:"seq"`
	Time  string `json:"time"`
	Level string `json:"level"`
	Text  string `json:"text"`
}

// Buffer is a bounded in-memory ring of the most recent log lines. It
// implements io.Writer so it can be combined with stderr via io.MultiWriter:
//
//	logger := log.New(io.MultiWriter(os.Stderr, buf), log.LevelInfo)
//
// The console polls Since with the cursor it last received, so no log line is
// missed or delivered twice.
type Buffer struct {
	mu    sync.Mutex
	lines []Line
	max   int
	seq   int64
}

// NewBuffer creates a buffer that keeps at most max entries (min 50).
func NewBuffer(max int) *Buffer {
	if max < 50 {
		max = 50
	}
	return &Buffer{max: max}
}

// Write implements io.Writer. The default logger writes exactly one complete
// line per call, already timestamped and leveled, so the buffer only has to
// split it back into its parts.
func (b *Buffer) Write(p []byte) (int, error) {
	for _, raw := range strings.Split(strings.TrimRight(string(p), "\r\n"), "\n") {
		if raw == "" {
			continue
		}
		b.push(parseLine(raw))
	}
	return len(p), nil
}

func (b *Buffer) push(line Line) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seq++
	line.Seq = b.seq
	b.lines = append(b.lines, line)
	if len(b.lines) > b.max {
		b.lines = b.lines[len(b.lines)-b.max:]
	}
}

// Since returns the entries with Seq > after and the cursor to pass next time.
// A cursor of 0 returns everything currently buffered.
func (b *Buffer) Since(after int64) ([]Line, int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if after < 0 {
		after = 0
	}
	start := 0
	for start < len(b.lines) && b.lines[start].Seq <= after {
		start++
	}
	out := make([]Line, len(b.lines)-start)
	copy(out, b.lines[start:])
	return out, b.seq
}

// Cursor returns the sequence number of the newest entry.
func (b *Buffer) Cursor() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.seq
}

// parseLine understands the logger's fixed format
// "2006-01-02T15:04:05Z07:00 LEVEL message". Anything else is kept verbatim.
func parseLine(raw string) Line {
	line := Line{Time: time.Now().Format(time.RFC3339), Level: "INFO", Text: raw}
	parts := strings.SplitN(raw, " ", 3)
	if len(parts) == 3 {
		if t, err := time.Parse(time.RFC3339, parts[0]); err == nil {
			line.Time = t.Format(time.RFC3339)
			line.Level = strings.TrimSpace(parts[1])
			line.Text = strings.TrimSpace(parts[2])
		}
	}
	return line
}
