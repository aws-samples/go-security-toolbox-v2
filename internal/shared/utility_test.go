package shared

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractAWSAccountFromARN(t *testing.T) {
	tests := []struct {
		name        string
		arn         string
		expected    string
		expectError bool
	}{
		{
			name:        "empty ARN",
			arn:         "",
			expected:    "",
			expectError: true,
		},
		{
			name:        "invalid ARN - too few parts",
			arn:         "arn:aws:iam",
			expected:    "",
			expectError: true,
		},
		{
			name:        "invalid ARN - exactly 5 parts",
			arn:         "arn:aws:iam::123456789012",
			expected:    "",
			expectError: true,
		},
		{
			name:        "valid IAM role ARN",
			arn:         "arn:aws:iam::123456789012:role/MyRole",
			expected:    "123456789012",
			expectError: false,
		},
		{
			name:        "valid IAM user ARN",
			arn:         "arn:aws:iam::123456789012:user/MyUser",
			expected:    "123456789012",
			expectError: false,
		},
		{
			name:        "valid IAM policy ARN",
			arn:         "arn:aws:iam::123456789012:policy/MyPolicy",
			expected:    "123456789012",
			expectError: false,
		},
		{
			name:        "valid S3 bucket ARN",
			arn:         "arn:aws:s3:::my-bucket/object",
			expected:    "",
			expectError: false,
		},
		{
			name:        "ARN with empty account field",
			arn:         "arn:aws:iam:::role/MyRole",
			expected:    "",
			expectError: false,
		},
		{
			name:        "ARN with extra colons",
			arn:         "arn:aws:iam::123456789012:role/My:Role:With:Colons",
			expected:    "123456789012",
			expectError: false,
		},
		{
			name:        "minimal valid ARN",
			arn:         "arn:aws:service::account:resource",
			expected:    "account",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ExtractAWSAccountFromARN(tt.arn)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Equal(t, tt.expected, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}