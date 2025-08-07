package errors

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAppError_Error(t *testing.T) {
	tests := []struct {
		name     string
		appError *AppError
		expected string
	}{
		{
			name:     "Error without cause",
			appError: New("test validation error", nil),
			expected: "test validation error",
		},
		{
			name:     "Error with cause",
			appError: New("API call failed", errors.New("network timeout")),
			expected: "API call failed: network timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.appError.Error()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAppError_Unwrap(t *testing.T) {
	tests := []struct {
		name     string
		appError *AppError
		expected error
	}{
		{
			name:     "Error with cause",
			appError: New("test error", errors.New("original error")),
			expected: errors.New("original error"),
		},
		{
			name:     "Error without cause",
			appError: New("test error", nil),
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.appError.Unwrap()
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				assert.Equal(t, tt.expected.Error(), result.Error())
			}
		})
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		cause    error
		expected string
	}{
		{
			name:     "Error without cause",
			message:  "validation failed",
			cause:    nil,
			expected: "validation failed",
		},
		{
			name:     "Error with cause",
			message:  "API error",
			cause:    errors.New("timeout"),
			expected: "API error: timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := New(tt.message, tt.cause)
			
			assert.Equal(t, tt.expected, result.Error())
			assert.Equal(t, tt.cause, result.Unwrap())
		})
	}
}