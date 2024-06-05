package shared

import (
	"fmt"
	"strings"
)

// ExtractAWSAccountFromARN takes an ARN and returns the AWS account number.
func ExtractAWSAccountFromARN(arn string) (string, error) {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return "", fmt.Errorf("invalid ARN: expected at least 6 parts, got %d", len(parts))
	}
	return parts[4], nil
}
