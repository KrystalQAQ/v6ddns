package log

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// File is an append-only log sink that rotates in place once the file would
// exceed maxBytes. One previous file is kept at path+".1". The volume is low
// because INFO only records changes and anomalies, so a single backup is
// enough to keep a full history window across rotations.
type File struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	f        *os.File
	size     int64
}

// NewFile opens (creating if needed) the log file at path. Missing parent
// directories are created with 0700; the file itself is 0600 because log lines
// carry the domain, addresses and errors even though secrets are redacted.
func NewFile(path string, maxBytes int64) (*File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("log: create log directory: %w", err)
	}
	w := &File{path: path, maxBytes: maxBytes}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *File) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("log: open %s: %w", w.path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("log: stat %s: %w", w.path, err)
	}
	w.f, w.size = f, info.Size()
	return nil
}

// Write appends p, rotating first when the write would exceed maxBytes. A
// maxBytes of zero or less disables rotation.
func (w *File) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return 0, os.ErrClosed
	}
	if w.maxBytes > 0 && w.size > 0 && w.size+int64(len(p)) > w.maxBytes {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *File) rotate() error {
	if err := w.f.Close(); err != nil {
		return fmt.Errorf("log: close before rotate: %w", err)
	}
	w.f = nil
	_ = os.Remove(w.path + ".1")
	if err := os.Rename(w.path, w.path+".1"); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("log: rotate %s: %w", w.path, err)
	}
	return w.open()
}

// Close closes the underlying file. It is safe to call more than once.
func (w *File) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
