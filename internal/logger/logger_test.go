package logger

import (
	"bytes"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoggers(t *testing.T) {
	tests := []struct {
		name     string
		logger   *log.Logger
		message  string
		expected string
	}{
		{"Info logger", Info, "test info", "INFO:"},
		{"Debug logger", Debug, "test debug", "DEBUG:"},
		{"Warn logger", Warn, "test warn", "WARN:"},
		{"Error logger", Error, "test error", "ERROR:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			origOutput := tt.logger.Writer()
			tt.logger.SetOutput(&buf)
			defer tt.logger.SetOutput(origOutput)

			tt.logger.Print(tt.message)
			output := buf.String()
			assert.Contains(t, output, tt.expected)
			assert.Contains(t, output, tt.message)
		})
	}
}

func TestLoggersPrintf(t *testing.T) {
	var buf bytes.Buffer
	origOutput := Info.Writer()
	Info.SetOutput(&buf)
	defer Info.SetOutput(origOutput)

	Info.Printf("test %s", "formatted")
	output := buf.String()
	assert.Contains(t, output, "INFO:")
	assert.Contains(t, output, "test formatted")
}