// Package log provides minimal leveled, timestamped structured logging with
// API-token redaction. All output goes to stderr so that it never contaminates
// stdout, which the TUI and --once mode may use for machine-readable data.
package log

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Level is a log severity. Lower values are more verbose.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

// String returns the conventional uppercase name of the level.
func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	case LevelFatal:
		return "FATAL"
	default:
		return fmt.Sprintf("LEVEL(%d)", int(l))
	}
}

// ParseLevel parses a case-insensitive level name. Unknown names return an error.
func ParseLevel(s string) (Level, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "DEBUG":
		return LevelDebug, nil
	case "INFO", "":
		return LevelInfo, nil
	case "WARN", "WARNING":
		return LevelWarn, nil
	case "ERROR":
		return LevelError, nil
	case "FATAL":
		return LevelFatal, nil
	default:
		return LevelInfo, fmt.Errorf("log: unknown level %q", s)
	}
}

// Logger is a leveled logger with a set of secrets that are redacted from
// every message and key/value pair before output.
type Logger struct {
	mu      sync.Mutex
	out     io.Writer
	level   Level
	secrets []string
}

// New creates a Logger that writes to w at the given level.
func New(w io.Writer, level Level) *Logger {
	if w == nil {
		w = os.Stderr
	}
	return &Logger{out: w, level: level}
}

// Default is the process-wide default logger (stderr, LevelInfo).
var Default = New(os.Stderr, LevelInfo)

// SetLevel changes the minimum level emitted by l.
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	l.level = level
	l.mu.Unlock()
}

// SetSecrets registers values that must be redacted from all log output.
// Passing an empty slice clears the list. Tokens shorter than 4 characters are
// ignored, matching config.MaskToken's safety threshold.
func (l *Logger) SetSecrets(secrets ...string) {
	l.mu.Lock()
	l.secrets = append(l.secrets[:0], secrets...)
	l.mu.Unlock()
}

// AddSecret registers one additional secret to redact.
func (l *Logger) AddSecret(secret string) {
	if secret == "" {
		return
	}
	l.mu.Lock()
	l.secrets = append(l.secrets, secret)
	l.mu.Unlock()
}

// Debug logs a message at DEBUG level.
func (l *Logger) Debug(msg string, kv ...any) { l.log(LevelDebug, msg, kv...) }

// Info logs a message at INFO level.
func (l *Logger) Info(msg string, kv ...any) { l.log(LevelInfo, msg, kv...) }

// Warn logs a message at WARN level.
func (l *Logger) Warn(msg string, kv ...any) { l.log(LevelWarn, msg, kv...) }

// Error logs a message at ERROR level.
func (l *Logger) Error(msg string, kv ...any) { l.log(LevelError, msg, kv...) }

// Fatal logs a message at FATAL level. It does not call os.Exit; callers decide
// how to terminate, which keeps the logger testable.
func (l *Logger) Fatal(msg string, kv ...any) { l.log(LevelFatal, msg, kv...) }

func (l *Logger) log(level Level, msg string, kv ...any) {
	l.mu.Lock()
	if level < l.level {
		l.mu.Unlock()
		return
	}
	fields := make([]string, 0, len(kv)+1)
	if msg != "" {
		fields = append(fields, redact(msg, l.secrets))
	}
	for i := 0; i+1 < len(kv); i += 2 {
		key := redact(fmt.Sprint(kv[i]), l.secrets)
		val := redact(fmt.Sprint(kv[i+1]), l.secrets)
		fields = append(fields, key+"="+val)
	}
	if len(kv)%2 == 1 {
		fields = append(fields, redact(fmt.Sprint(kv[len(kv)-1]), l.secrets))
	}
	line := fmt.Sprintf("%s %-5s %s\n", time.Now().Format(time.RFC3339), level, strings.Join(fields, " "))
	_, _ = io.WriteString(l.out, line)
	l.mu.Unlock()
}

// redact applies every registered secret as a literal substring replacement.
func redact(s string, secrets []string) string {
	for _, secret := range secrets {
		if len(secret) < 4 {
			continue
		}
		s = strings.ReplaceAll(s, secret, "***")
	}
	return s
}

// Package-level convenience wrappers around Default.

func Debug(msg string, kv ...any) { Default.Debug(msg, kv...) }
func Info(msg string, kv ...any)  { Default.Info(msg, kv...) }
func Warn(msg string, kv ...any)  { Default.Warn(msg, kv...) }
func Error(msg string, kv ...any) { Default.Error(msg, kv...) }
func Fatal(msg string, kv ...any) { Default.Fatal(msg, kv...) }
