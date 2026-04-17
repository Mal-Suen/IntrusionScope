// Package logger provides structured logging for IntrusionScope
package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

// Level represents log level
type Level int

const (
	// Debug level
	Debug Level = iota
	// Info level
	Info
	// Warn level
	Warn
	// Error level
	Error
)

func (l Level) String() string {
	switch l {
	case Debug:
		return "DEBUG"
	case Info:
		return "INFO"
	case Warn:
		return "WARN"
	case Error:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Logger provides structured logging
type Logger struct {
	level     Level
	format    string // "json" or "text"
	writer    io.Writer
	mu        sync.Mutex
	fields    map[string]interface{}
}

// New creates a new logger
func New(verbose bool) *Logger {
	level := Info
	if verbose {
		level = Debug
	}

	return &Logger{
		level:  level,
		format: "json",
		writer: os.Stderr,
		fields: make(map[string]interface{}),
	}
}

// NewWithConfig creates a logger with specific configuration
func NewWithConfig(level string, format string, writer io.Writer) *Logger {
	l := Info
	switch level {
	case "debug":
		l = Debug
	case "warn":
		l = Warn
	case "error":
		l = Error
	}

	if writer == nil {
		writer = os.Stderr
	}

	return &Logger{
		level:  l,
		format: format,
		writer: writer,
		fields: make(map[string]interface{}),
	}
}

// WithFields returns a new logger with additional fields
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	newLogger := &Logger{
		level:  l.level,
		format: l.format,
		writer: l.writer,
		fields: make(map[string]interface{}),
	}

	// Copy existing fields
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}

	// Add new fields
	for k, v := range fields {
		newLogger.fields[k] = v
	}

	return newLogger
}

// log writes a log entry
func (l *Logger) log(level Level, msg string, args ...interface{}) {
	if level < l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Build entry with base fields
	entry := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"level":     level.String(),
		"message":   msg,
	}

	// Add existing fields
	for k, v := range l.fields {
		entry[k] = v
	}

	// Process args as key-value pairs (must be even number)
	for i := 0; i < len(args)-1; i += 2 {
		if key, ok := args[i].(string); ok {
			entry[key] = args[i+1]
		}
	}

	if l.format == "json" {
		data, err := json.Marshal(entry)
		if err != nil {
			log.Printf("error marshaling log entry: %v", err)
			return
		}
		fmt.Fprintln(l.writer, string(data))
	} else {
		// Text format
		fmt.Fprintf(l.writer, "[%s] %s: %s", entry["timestamp"], level.String(), entry["message"])
		for k, v := range l.fields {
			fmt.Fprintf(l.writer, " %s=%v", k, v)
		}
		fmt.Fprintln(l.writer)
	}
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, args ...interface{}) {
	l.log(Debug, msg, args...)
}

// Info logs an info message
func (l *Logger) Info(msg string, args ...interface{}) {
	l.log(Info, msg, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, args ...interface{}) {
	l.log(Warn, msg, args...)
}

// Error logs an error message
func (l *Logger) Error(msg string, args ...interface{}) {
	l.log(Error, msg, args...)
}

// Fatal logs an error message and exits
func (l *Logger) Fatal(msg string, args ...interface{}) {
	l.log(Error, msg, args...)
	os.Exit(1)
}
