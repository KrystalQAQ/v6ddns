package log

import (
	"strings"
	"testing"
)

func TestBufferSinceIsIncremental(t *testing.T) {
	b := NewBuffer(50)
	logger := New(b, LevelInfo)
	logger.Info("first", "n", 1)
	logger.Warn("second")

	lines, cursor := b.Since(0)
	if len(lines) != 2 || cursor != 2 {
		t.Fatalf("Since(0) = %d lines, cursor %d", len(lines), cursor)
	}
	if lines[0].Level != "INFO" || !strings.Contains(lines[0].Text, "first") {
		t.Errorf("first line = %+v", lines[0])
	}
	if lines[1].Level != "WARN" || lines[1].Text != "second" {
		t.Errorf("second line = %+v", lines[1])
	}
	if lines[1].Seq != 2 {
		t.Errorf("sequence = %d, want 2", lines[1].Seq)
	}

	lines, cursor = b.Since(cursor)
	if len(lines) != 0 || cursor != 2 {
		t.Fatalf("Since(2) = %d lines, cursor %d", len(lines), cursor)
	}

	logger.Error("third")
	lines, cursor = b.Since(2)
	if len(lines) != 1 || lines[0].Text != "third" || cursor != 3 {
		t.Fatalf("Since(2) after write = %+v, cursor %d", lines, cursor)
	}
}

func TestBufferDropsOldLines(t *testing.T) {
	b := NewBuffer(50)
	for i := 0; i < 60; i++ {
		b.Write([]byte("2026-01-01T00:00:00Z INFO line\n"))
	}
	lines, cursor := b.Since(0)
	if len(lines) != 50 {
		t.Fatalf("kept %d lines, want 50", len(lines))
	}
	if cursor != 60 {
		t.Fatalf("cursor = %d, want 60", cursor)
	}
	if lines[0].Seq != 11 || lines[49].Seq != 60 {
		t.Fatalf("kept sequence range %d..%d", lines[0].Seq, lines[49].Seq)
	}
}

func TestBufferKeepsUnparseableLines(t *testing.T) {
	b := NewBuffer(50)
	b.Write([]byte("plain text without a timestamp\n"))
	lines, _ := b.Since(0)
	if len(lines) != 1 || lines[0].Text == "" || lines[0].Level != "INFO" {
		t.Fatalf("lines = %+v", lines)
	}
}

func TestBufferHandlesMultiLineWrites(t *testing.T) {
	b := NewBuffer(50)
	b.Write([]byte("2026-01-01T00:00:00Z INFO one\n2026-01-01T00:00:01Z ERROR two\r\n\n"))
	lines, cursor := b.Since(0)
	if len(lines) != 2 || cursor != 2 {
		t.Fatalf("lines = %+v, cursor = %d", lines, cursor)
	}
	if lines[1].Level != "ERROR" || lines[1].Text != "two" {
		t.Errorf("second = %+v", lines[1])
	}
}
