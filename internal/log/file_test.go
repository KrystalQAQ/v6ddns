package log

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileRotatesAndAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "v6ddns.log")
	w, err := NewFile(path, 64)
	if err != nil {
		t.Fatal(err)
	}

	first := strings.Repeat("a", 40) + "\n"
	if _, err := w.Write([]byte(first)); err != nil {
		t.Fatal(err)
	}
	second := strings.Repeat("b", 40) + "\n"
	if _, err := w.Write([]byte(second)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	if got := readFile(t, path); got != second {
		t.Errorf("current log = %q, want %q", got, second)
	}
	if got := readFile(t, path+".1"); got != first {
		t.Errorf("rotated log = %q, want %q", got, first)
	}

	// Reopening must append to the existing file, not truncate it.
	w2, err := NewFile(path, 64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w2.Write([]byte("c\n")); err != nil {
		t.Fatal(err)
	}
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); got != second+"c\n" {
		t.Errorf("reopened log = %q, want %q", got, second+"c\n")
	}
}

func TestFileCloseTwice(t *testing.T) {
	w, err := NewFile(filepath.Join(t.TempDir(), "v6ddns.log"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("x")); err == nil {
		t.Error("Write after Close should fail")
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
