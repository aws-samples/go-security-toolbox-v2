package logger

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// Logger defines the interface for structured logging with four levels
type Logger interface {
	// Info logs informational messages for general application flow
	Info(msg string, fields ...interface{})
	// Debug logs detailed information for debugging and troubleshooting
	Debug(msg string, fields ...interface{})
	// Warn logs warning messages for potentially harmful situations
	Warn(msg string, fields ...interface{})
	// Error logs error messages for serious problems that need attention
	Error(msg string, fields ...interface{})
}

type defaultLogger struct {
	infoLogger  *log.Logger
	debugLogger *log.Logger
	warnLogger  *log.Logger
	errorLogger *log.Logger
}

func NewLogger() Logger {
	return &defaultLogger{
		infoLogger:  log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile),
		debugLogger: log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile),
		warnLogger:  log.New(os.Stdout, "WARN: ", log.Ldate|log.Ltime|log.Lshortfile),
		errorLogger: log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile),
	}
}

func (l *defaultLogger) Info(msg string, fields ...interface{}) {
	msg = sanitize(msg)
	fields = sanitizeFields(fields)
	if len(fields) > 0 {
		l.infoLogger.Printf(msg, fields...)
	} else {
		l.infoLogger.Print(msg)
	}
}

func (l *defaultLogger) Debug(msg string, fields ...interface{}) {
	msg = sanitize(msg)
	fields = sanitizeFields(fields)
	if len(fields) > 0 {
		l.debugLogger.Printf(msg, fields...)
	} else {
		l.debugLogger.Print(msg)
	}
}

func (l *defaultLogger) Warn(msg string, fields ...interface{}) {
	msg = sanitize(msg)
	fields = sanitizeFields(fields)
	if len(fields) > 0 {
		l.warnLogger.Printf(msg, fields...)
	} else {
		l.warnLogger.Print(msg)
	}
}

func (l *defaultLogger) Error(msg string, fields ...interface{}) {
	msg = sanitize(msg)
	fields = sanitizeFields(fields)
	if len(fields) > 0 {
		l.errorLogger.Printf(msg, fields...)
	} else {
		l.errorLogger.Print(msg)
	}
}

// sanitize removes newlines and carriage returns to prevent log injection
func sanitize(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// sanitizeFields sanitizes all string fields in the variadic arguments
func sanitizeFields(fields []interface{}) []interface{} {
	for i, field := range fields {
		if str, ok := field.(string); ok {
			fields[i] = sanitize(str)
		} else if str, ok := field.(fmt.Stringer); ok {
			fields[i] = sanitize(str.String())
		}
	}
	return fields
}

// NoOpLogger is a logger implementation that discards all log messages.
// Useful for testing scenarios where logging output is not needed.
type NoOpLogger struct{}

// Info discards informational log messages
func (NoOpLogger) Info(msg string, fields ...interface{}) {}

// Debug discards debug log messages
func (NoOpLogger) Debug(msg string, fields ...interface{}) {}

// Warn discards warning log messages
func (NoOpLogger) Warn(msg string, fields ...interface{}) {}

// Error discards error log messages
func (NoOpLogger) Error(msg string, fields ...interface{}) {}