package gui

import (
	"strings"
	"sync"

	"fyne.io/fyne/v2"
)

const maxLogLines = 200

// guiLogWriter implements io.Writer for log.Logger. It buffers the log in the
// App and pushes it to the dashboard widget on the Fyne goroutine.
type guiLogWriter struct {
	g   *App
	mu  sync.Mutex
	buf []string
}

func (w *guiLogWriter) Write(p []byte) (int, error) {
	line := strings.TrimSuffix(string(p), "\n")
	w.mu.Lock()
	w.buf = append(w.buf, line)
	if len(w.buf) > maxLogLines {
		w.buf = w.buf[len(w.buf)-maxLogLines:]
	}
	lines := strings.Join(w.buf, "\n")
	w.mu.Unlock()
	if w.g.logView != nil {
		fyne.Do(func() {
			w.g.logView.SetText(lines)
		})
	}
	return len(p), nil
}
