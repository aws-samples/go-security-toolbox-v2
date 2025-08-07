package logger

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultLogger(t *testing.T) {
	tests := []struct {
		name     string
		logFunc  func(Logger, string, ...interface{})
		message  string
		fields   []interface{}
		expected string
	}{
		{
			name:     "Info without fields",
			logFunc:  func(l Logger, msg string, fields ...interface{}) { l.Info(msg, fields...) },
			message:  "test info message",
			fields:   nil,
			expected: "INFO:",
		},
		{
			name:     "Info with fields",
			logFunc:  func(l Logger, msg string, fields ...interface{}) { l.Info(msg, fields...) },
			message:  "test info message %s",
			fields:   []interface{}{"with field"},
			expected: "INFO:",
		},
		{
			name:     "Debug without fields",
			logFunc:  func(l Logger, msg string, fields ...interface{}) { l.Debug(msg, fields...) },
			message:  "test debug message",
			fields:   nil,
			expected: "DEBUG:",
		},
		{
			name:     "Warn without fields",
			logFunc:  func(l Logger, msg string, fields ...interface{}) { l.Warn(msg, fields...) },
			message:  "test warn message",
			fields:   nil,
			expected: "WARN:",
		},
		{
			name:     "Error without fields",
			logFunc:  func(l Logger, msg string, fields ...interface{}) { l.Error(msg, fields...) },
			message:  "test error message",
			fields:   nil,
			expected: "ERROR:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := &defaultLogger{
				infoLogger:  log.New(&buf, "INFO: ", 0),
				debugLogger: log.New(&buf, "DEBUG: ", 0),
				warnLogger:  log.New(&buf, "WARN: ", 0),
				errorLogger: log.New(&buf, "ERROR: ", 0),
			}

			tt.logFunc(logger, tt.message, tt.fields...)

			output := buf.String()
			assert.Contains(t, output, tt.expected)
			assert.Contains(t, output, strings.Split(tt.message, " %")[0])
		})
	}
}

func TestNoOpLogger(t *testing.T) {
	tests := []struct {
		name    string
		logFunc func(Logger)
	}{
		{
			name:    "Info does nothing",
			logFunc: func(l Logger) { l.Info("test") },
		},
		{
			name:    "Debug does nothing",
			logFunc: func(l Logger) { l.Debug("test") },
		},
		{
			name:    "Warn does nothing",
			logFunc: func(l Logger) { l.Warn("test") },
		},
		{
			name:    "Error does nothing",
			logFunc: func(l Logger) { l.Error("test") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NoOpLogger{}
			// Should not panic
			assert.NotPanics(t, func() {
				tt.logFunc(logger)
			})
		})
	}
}