package shared

import (
	"testing"

	accessAnalyzerTypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/logger"
	"github.com/stretchr/testify/assert"
)

func TestConvertReasonsToString(t *testing.T) {
	tests := []struct {
		name     string
		reasons  []accessAnalyzerTypes.ReasonSummary
		log      logger.Logger
		expected []string
	}{
		{
			name:     "nil reasons with logger",
			reasons:  nil,
			log:      logger.NewLogger(),
			expected: []string(nil),
		},
		{
			name:     "nil reasons without logger",
			reasons:  nil,
			log:      nil,
			expected: []string(nil),
		},
		{
			name:    "empty reasons slice",
			reasons: []accessAnalyzerTypes.ReasonSummary{},
			log:     logger.NewLogger(),
			expected: []string(nil),
		},
		{
			name: "single reason with description",
			reasons: []accessAnalyzerTypes.ReasonSummary{
				{Description: stringPtr("Test reason 1")},
			},
			log:      logger.NewLogger(),
			expected: []string{"Test reason 1"},
		},
		{
			name: "multiple reasons with descriptions",
			reasons: []accessAnalyzerTypes.ReasonSummary{
				{Description: stringPtr("Test reason 1")},
				{Description: stringPtr("Test reason 2")},
				{Description: stringPtr("Test reason 3")},
			},
			log:      logger.NewLogger(),
			expected: []string{"Test reason 1", "Test reason 2", "Test reason 3"},
		},
		{
			name: "reasons with nil descriptions",
			reasons: []accessAnalyzerTypes.ReasonSummary{
				{Description: nil},
				{Description: stringPtr("Valid reason")},
				{Description: nil},
			},
			log:      logger.NewLogger(),
			expected: []string{"Valid reason"},
		},
		{
			name: "mixed valid and nil descriptions",
			reasons: []accessAnalyzerTypes.ReasonSummary{
				{Description: stringPtr("First reason")},
				{Description: nil},
				{Description: stringPtr("Second reason")},
				{Description: stringPtr("")},
			},
			log:      logger.NewLogger(),
			expected: []string{"First reason", "Second reason"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConvertReasonsToString(tt.reasons, tt.log)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func stringPtr(s string) *string {
	return &s
}