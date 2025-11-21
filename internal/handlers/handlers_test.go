package handlers

import (
	"context"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
)

func TestConfig(t *testing.T) {
	config := Config{
		PrecompliantIamIdentities: []string{"arn:aws:iam::123456789012:role/test-role"},
		RestrictedActions:         []string{"s3:DeleteBucket", "iam:CreateRole"},
		TestMode:                  true,
	}

	assert.Len(t, config.PrecompliantIamIdentities, 1)
	assert.Equal(t, "arn:aws:iam::123456789012:role/test-role", config.PrecompliantIamIdentities[0])
	assert.Len(t, config.RestrictedActions, 2)
	assert.Contains(t, config.RestrictedActions, "s3:DeleteBucket")
	assert.Contains(t, config.RestrictedActions, "iam:CreateRole")
	assert.True(t, config.TestMode)
}

func TestRouteConfigRuleUnsupported(t *testing.T) {
	event := events.ConfigEvent{
		ConfigRuleName: "unsupported-rule",
	}

	// Test with empty AWS config - will fail at config loading but tests routing logic
	var cfg aws.Config
	err := RouteConfigRule(context.TODO(), event, cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported config rule")
}
