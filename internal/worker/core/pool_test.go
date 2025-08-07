package core

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/logger"
	"github.com/stretchr/testify/assert"
)

// Mock processor for testing
type mockProcessor struct {
	processFunc func(ctx context.Context, input string) (string, error)
}

func (m *mockProcessor) Process(ctx context.Context, input string) (string, error) {
	if m.processFunc != nil {
		return m.processFunc(ctx, input)
	}
	return "processed-" + input, nil
}

// Mock error handler for testing
type mockErrorHandler struct {
	errors []error
	inputs []interface{}
	mu     sync.Mutex
}

func (m *mockErrorHandler) HandleError(ctx context.Context, err error, input interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors = append(m.errors, err)
	m.inputs = append(m.inputs, input)
}

func (m *mockErrorHandler) getErrors() []error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]error{}, m.errors...)
}

func (m *mockErrorHandler) getInputs() []interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]interface{}{}, m.inputs...)
}

func TestGetWorkerCount(t *testing.T) {
	tests := []struct {
		name     string
		config   *int
		envValue string
		expected int
	}{
		{
			name:     "config provided",
			config:   intPtr(5),
			envValue: "",
			expected: 5,
		},
		{
			name:     "no config, valid env",
			config:   nil,
			envValue: "10",
			expected: 10,
		},
		{
			name:     "no config, invalid env",
			config:   nil,
			envValue: "invalid",
			expected: DefaultWorkerCount,
		},
		{
			name:     "no config, negative env",
			config:   nil,
			envValue: "-1",
			expected: DefaultWorkerCount,
		},
		{
			name:     "no config, zero env",
			config:   nil,
			envValue: "0",
			expected: DefaultWorkerCount,
		},
		{
			name:     "no config, no env",
			config:   nil,
			envValue: "",
			expected: DefaultWorkerCount,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable
			if tt.envValue != "" {
				os.Setenv(WorkerCountEnvVar, tt.envValue)
			} else {
				os.Unsetenv(WorkerCountEnvVar)
			}
			defer os.Unsetenv(WorkerCountEnvVar)

			result := getWorkerCount(tt.config)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewPool(t *testing.T) {
	tests := []struct {
		name           string
		config         PoolConfig
		expectedWorkers int
		expectedBuffer  int
	}{
		{
			name: "default config",
			config: PoolConfig{
				BufferSize: 0,
				Logger:     nil,
			},
			expectedWorkers: DefaultWorkerCount,
			expectedBuffer:  DefaultBufferSize,
		},
		{
			name: "custom config",
			config: PoolConfig{
				WorkerCount: intPtr(5),
				BufferSize:  200,
				Logger:      logger.NewLogger(),
			},
			expectedWorkers: 5,
			expectedBuffer:  200,
		},
		{
			name: "negative buffer size",
			config: PoolConfig{
				BufferSize: -10,
			},
			expectedWorkers: DefaultWorkerCount,
			expectedBuffer:  DefaultBufferSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := &mockProcessor{}
			errorHandler := &mockErrorHandler{}

			pool := NewPool[string, string](tt.config, processor, errorHandler)

			assert.NotNil(t, pool)
			assert.Equal(t, tt.expectedWorkers, pool.workerCount)
			assert.Equal(t, tt.expectedBuffer, cap(pool.jobQueue))
			assert.Equal(t, tt.expectedBuffer, cap(pool.resultChan))
			assert.Equal(t, tt.expectedBuffer, cap(pool.errorChan))
			assert.NotNil(t, pool.logger)
		})
	}
}

func TestPool_StartAndStop(t *testing.T) {
	processor := &mockProcessor{}
	errorHandler := &mockErrorHandler{}
	config := PoolConfig{
		WorkerCount: intPtr(2),
		BufferSize:  10,
	}

	pool := NewPool[string, string](config, processor, errorHandler)
	ctx := context.Background()

	// Test start
	pool.Start(ctx)
	assert.NotNil(t, pool.ctx)
	assert.NotNil(t, pool.cancel)

	// Test stop
	pool.Stop()
	
	// Verify channels are closed
	select {
	case _, ok := <-pool.resultChan:
		assert.False(t, ok, "result channel should be closed")
	default:
		t.Error("result channel should be closed")
	}

	select {
	case _, ok := <-pool.errorChan:
		assert.False(t, ok, "error channel should be closed")
	default:
		t.Error("error channel should be closed")
	}
}

func TestPool_Submit(t *testing.T) {
	processor := &mockProcessor{}
	errorHandler := &mockErrorHandler{}
	config := PoolConfig{
		WorkerCount: intPtr(1),
		BufferSize:  2,
	}

	pool := NewPool[string, string](config, processor, errorHandler)
	ctx := context.Background()
	pool.Start(ctx)
	defer pool.Stop()

	tests := []struct {
		name     string
		job      string
		expected bool
	}{
		{"first job", "job1", true},
		{"second job", "job2", true},
		{"third job (should fail - buffer full)", "job3", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pool.Submit(tt.job)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPool_ProcessingSuccess(t *testing.T) {
	processor := &mockProcessor{
		processFunc: func(ctx context.Context, input string) (string, error) {
			return "processed-" + input, nil
		},
	}
	errorHandler := &mockErrorHandler{}
	config := PoolConfig{
		WorkerCount: intPtr(1),
		BufferSize:  10,
	}

	pool := NewPool[string, string](config, processor, errorHandler)
	ctx := context.Background()
	pool.Start(ctx)
	defer pool.Stop()

	// Submit job
	success := pool.Submit("test")
	assert.True(t, success)

	// Wait for result
	select {
	case result := <-pool.Results():
		assert.Equal(t, "processed-test", result)
	case <-time.After(time.Second):
		t.Error("timeout waiting for result")
	}

	// Verify no errors
	assert.Empty(t, errorHandler.getErrors())
}

func TestPool_ProcessingError(t *testing.T) {
	testError := errors.New("processing error")
	processor := &mockProcessor{
		processFunc: func(ctx context.Context, input string) (string, error) {
			return "", testError
		},
	}
	errorHandler := &mockErrorHandler{}
	config := PoolConfig{
		WorkerCount: intPtr(1),
		BufferSize:  10,
	}

	pool := NewPool[string, string](config, processor, errorHandler)
	ctx := context.Background()
	pool.Start(ctx)
	defer pool.Stop()

	// Submit job
	success := pool.Submit("test")
	assert.True(t, success)

	// Wait for error
	select {
	case err := <-pool.Errors():
		assert.Equal(t, testError, err)
	case <-time.After(time.Second):
		t.Error("timeout waiting for error")
	}

	// Verify error handler was called
	errors := errorHandler.getErrors()
	inputs := errorHandler.getInputs()
	assert.Len(t, errors, 1)
	assert.Equal(t, testError, errors[0])
	assert.Len(t, inputs, 1)
	assert.Equal(t, "test", inputs[0])
}

func TestPool_WithTimeout(t *testing.T) {
	timeout := 100 * time.Millisecond
	processor := &mockProcessor{
		processFunc: func(ctx context.Context, input string) (string, error) {
			// Simulate slow processing
			select {
			case <-time.After(200 * time.Millisecond):
				return "processed-" + input, nil
			case <-ctx.Done():
				return "", ctx.Err()
			}
		},
	}
	errorHandler := &mockErrorHandler{}
	config := PoolConfig{
		WorkerCount: intPtr(1),
		BufferSize:  10,
		Timeout:     &timeout,
	}

	pool := NewPool[string, string](config, processor, errorHandler)
	ctx := context.Background()
	pool.Start(ctx)
	defer pool.Stop()

	// Submit job
	success := pool.Submit("test")
	assert.True(t, success)

	// Wait for timeout error
	select {
	case err := <-pool.Errors():
		assert.Equal(t, context.DeadlineExceeded, err)
	case <-time.After(time.Second):
		t.Error("timeout waiting for timeout error")
	}
}

func TestPool_ContextCancellation(t *testing.T) {
	processor := &mockProcessor{
		processFunc: func(ctx context.Context, input string) (string, error) {
			// Wait for context cancellation
			<-ctx.Done()
			return "", ctx.Err()
		},
	}
	errorHandler := &mockErrorHandler{}
	config := PoolConfig{
		WorkerCount: intPtr(1),
		BufferSize:  10,
	}

	pool := NewPool[string, string](config, processor, errorHandler)
	ctx, cancel := context.WithCancel(context.Background())
	pool.Start(ctx)
	defer pool.Stop()

	// Submit job
	success := pool.Submit("test")
	assert.True(t, success)

	// Cancel context
	cancel()

	// Wait for cancellation error
	select {
	case err := <-pool.Errors():
		assert.Equal(t, context.Canceled, err)
	case <-time.After(time.Second):
		t.Error("timeout waiting for cancellation error")
	}
}

func intPtr(i int) *int {
	return &i
}