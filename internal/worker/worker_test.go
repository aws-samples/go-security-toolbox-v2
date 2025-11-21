package worker

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	accessAnalyzerTypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/stretchr/testify/assert"
)

func TestConvertReasonsToString(t *testing.T) {
	tests := []struct {
		name     string
		reasons  []accessAnalyzerTypes.ReasonSummary
		expected []string
	}{
		{
			name:     "Empty reasons",
			reasons:  []accessAnalyzerTypes.ReasonSummary{},
			expected: nil,
		},
		{
			name: "Single reason",
			reasons: []accessAnalyzerTypes.ReasonSummary{
				{Description: aws.String("Test reason")},
			},
			expected: []string{"Test reason"},
		},
		{
			name: "Multiple reasons",
			reasons: []accessAnalyzerTypes.ReasonSummary{
				{Description: aws.String("Reason 1")},
				{Description: aws.String("Reason 2")},
			},
			expected: []string{"Reason 1", "Reason 2"},
		},
		{
			name: "Reasons with empty descriptions",
			reasons: []accessAnalyzerTypes.ReasonSummary{
				{Description: aws.String("Valid reason")},
				{Description: aws.String("")},
				{Description: aws.String("Another valid reason")},
			},
			expected: []string{"Valid reason", "Another valid reason"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertReasonsToString(tt.reasons)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractAccountFromArn(t *testing.T) {
	tests := []struct {
		name     string
		arn      string
		expected string
	}{
		{
			name:     "Valid IAM role ARN",
			arn:      "arn:aws:iam::123456789012:role/test-role",
			expected: "123456789012",
		},
		{
			name:     "Valid IAM user ARN",
			arn:      "arn:aws:iam::987654321098:user/test-user",
			expected: "987654321098",
		},
		{
			name:     "Invalid ARN format",
			arn:      "invalid-arn",
			expected: "",
		},
		{
			name:     "Empty ARN",
			arn:      "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractAccountFromArn(tt.arn)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPolicyScanResult(t *testing.T) {
	result := PolicyScanResult{
		PrincipalArn:     "arn:aws:iam::123456789012:role/test-role",
		PrincipalType:    PrincipalTypeRole,
		ComplianceStatus: configServiceTypes.ComplianceTypeCompliant,
		Annotation:       "Test annotation",
		Timestamp:        time.Now(),
	}

	assert.Equal(t, "arn:aws:iam::123456789012:role/test-role", result.PrincipalArn)
	assert.Equal(t, PrincipalTypeRole, result.PrincipalType)
	assert.Equal(t, configServiceTypes.ComplianceTypeCompliant, result.ComplianceStatus)
	assert.Equal(t, "Test annotation", result.Annotation)
	assert.False(t, result.Timestamp.IsZero())
}

func TestOrphanPolicyResult(t *testing.T) {
	result := OrphanPolicyResult{
		PolicyArn:        "arn:aws:iam::123456789012:policy/test-policy",
		PolicyName:       "test-policy",
		ComplianceStatus: configServiceTypes.ComplianceTypeNonCompliant,
		Annotation:       "Policy is not attached to any IAM principals",
		Timestamp:        time.Now(),
	}

	assert.Equal(t, "arn:aws:iam::123456789012:policy/test-policy", result.PolicyArn)
	assert.Equal(t, "test-policy", result.PolicyName)
	assert.Equal(t, configServiceTypes.ComplianceTypeNonCompliant, result.ComplianceStatus)
	assert.Equal(t, "Policy is not attached to any IAM principals", result.Annotation)
	assert.False(t, result.Timestamp.IsZero())
}