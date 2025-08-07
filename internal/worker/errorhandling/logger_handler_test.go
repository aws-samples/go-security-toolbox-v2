package errorhandling

import (
	"context"
	"errors"
	"testing"

	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/logger"
	"github.com/stretchr/testify/assert"
)

// Mock logger for testing
type mockLogger struct {
	errorCalls []logCall
	debugCalls []logCall
}

type logCall struct {
	format string
	args   []interface{}
}

func (m *mockLogger) Info(format string, args ...interface{}) {}
func (m *mockLogger) Debug(format string, args ...interface{}) {
	m.debugCalls = append(m.debugCalls, logCall{format: format, args: args})
}
func (m *mockLogger) Warn(format string, args ...interface{}) {}
func (m *mockLogger) Error(format string, args ...interface{}) {
	m.errorCalls = append(m.errorCalls, logCall{format: format, args: args})
}

func TestNewLoggerErrorHandler(t *testing.T) {
	tests := []struct {
		name   string
		logger logger.Logger
	}{
		{
			name:   "with real logger",
			logger: logger.NewLogger(),
		},
		{
			name:   "with mock logger",
			logger: &mockLogger{},
		},
		{
			name:   "with nil logger",
			logger: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewLoggerErrorHandler(tt.logger)
			
			assert.NotNil(t, handler)
			assert.Equal(t, tt.logger, handler.logger)
		})
	}
}

func TestLoggerErrorHandler_HandleError(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		input interface{}
	}{
		{
			name:  "simple error with string input",
			err:   errors.New("test error"),
			input: "test-input",
		},
		{
			name:  "complex error with struct input",
			err:   errors.New("complex error message"),
			input: struct{ Name string }{Name: "test"},
		},
		{
			name:  "nil input",
			err:   errors.New("error with nil input"),
			input: nil,
		},
		{
			name:  "empty error message",
			err:   errors.New(""),
			input: "test-input",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLog := &mockLogger{}
			handler := NewLoggerErrorHandler(mockLog)
			
			ctx := context.Background()
			
			// This should not panic
			assert.NotPanics(t, func() {
				handler.HandleError(ctx, tt.err, tt.input)
			})
			
			// Verify error was logged
			assert.Len(t, mockLog.errorCalls, 1)
			assert.Contains(t, mockLog.errorCalls[0].format, "Policy scan error")
			
			// Verify debug was logged
			assert.Len(t, mockLog.debugCalls, 1)
			assert.Contains(t, mockLog.debugCalls[0].format, "Error CSV record")
		})
	}
}

func TestLoggerErrorHandler_HandleError_WithContext(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
	}{
		{
			name: "with background context",
			ctx:  context.Background(),
		},
		{
			name: "with cancelled context",
			ctx:  func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			}(),
		},
		{
			name: "with nil context",
			ctx:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLog := &mockLogger{}
			handler := NewLoggerErrorHandler(mockLog)
			
			err := errors.New("test error")
			input := "test-input"
			
			// Should handle any context without panicking
			assert.NotPanics(t, func() {
				handler.HandleError(tt.ctx, err, input)
			})
			
			// Verify logging occurred
			assert.Len(t, mockLog.errorCalls, 1)
			assert.Len(t, mockLog.debugCalls, 1)
		})
	}
}