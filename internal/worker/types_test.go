package worker

import (
	"testing"
	"time"

	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/stretchr/testify/assert"
)

func TestPolicyScanRequest(t *testing.T) {
	tests := []struct {
		name     string
		request  PolicyScanRequest
		expected PolicyScanRequest
	}{
		{
			name: "complete policy scan request",
			request: PolicyScanRequest{
				PrincipalArn:  "arn:aws:iam::123456789012:role/TestRole",
				PrincipalType: "AWS::IAM::Role",
				PrincipalName: "TestRole",
				AccountID:     "123456789012",
			},
			expected: PolicyScanRequest{
				PrincipalArn:  "arn:aws:iam::123456789012:role/TestRole",
				PrincipalType: "AWS::IAM::Role",
				PrincipalName: "TestRole",
				AccountID:     "123456789012",
			},
		},
		{
			name: "empty policy scan request",
			request: PolicyScanRequest{
				PrincipalArn:  "",
				PrincipalType: "",
				PrincipalName: "",
				AccountID:     "",
			},
			expected: PolicyScanRequest{
				PrincipalArn:  "",
				PrincipalType: "",
				PrincipalName: "",
				AccountID:     "",
			},
		},
		{
			name: "user policy scan request",
			request: PolicyScanRequest{
				PrincipalArn:  "arn:aws:iam::123456789012:user/TestUser",
				PrincipalType: "AWS::IAM::User",
				PrincipalName: "TestUser",
				AccountID:     "123456789012",
			},
			expected: PolicyScanRequest{
				PrincipalArn:  "arn:aws:iam::123456789012:user/TestUser",
				PrincipalType: "AWS::IAM::User",
				PrincipalName: "TestUser",
				AccountID:     "123456789012",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.request)
			assert.Equal(t, tt.expected.PrincipalArn, tt.request.PrincipalArn)
			assert.Equal(t, tt.expected.PrincipalType, tt.request.PrincipalType)
			assert.Equal(t, tt.expected.PrincipalName, tt.request.PrincipalName)
			assert.Equal(t, tt.expected.AccountID, tt.request.AccountID)
		})
	}
}

func TestPolicyComplianceResult(t *testing.T) {
	tests := []struct {
		name     string
		result   PolicyComplianceResult
		expected PolicyComplianceResult
	}{
		{
			name: "compliant policy result",
			result: PolicyComplianceResult{
				PolicyName:       "TestPolicy",
				ComplianceStatus: configServiceTypes.ComplianceTypeCompliant,
				Reasons:          []string{},
				Message:          "Policy is compliant",
			},
			expected: PolicyComplianceResult{
				PolicyName:       "TestPolicy",
				ComplianceStatus: configServiceTypes.ComplianceTypeCompliant,
				Reasons:          []string{},
				Message:          "Policy is compliant",
			},
		},
		{
			name: "non-compliant policy result",
			result: PolicyComplianceResult{
				PolicyName:       "ViolatingPolicy",
				ComplianceStatus: configServiceTypes.ComplianceTypeNonCompliant,
				Reasons:          []string{"Contains restricted action", "Overly permissive"},
				Message:          "Policy violates security rules",
			},
			expected: PolicyComplianceResult{
				PolicyName:       "ViolatingPolicy",
				ComplianceStatus: configServiceTypes.ComplianceTypeNonCompliant,
				Reasons:          []string{"Contains restricted action", "Overly permissive"},
				Message:          "Policy violates security rules",
			},
		},
		{
			name: "insufficient data result",
			result: PolicyComplianceResult{
				PolicyName:       "UnknownPolicy",
				ComplianceStatus: configServiceTypes.ComplianceTypeInsufficientData,
				Reasons:          []string{"Unable to analyze policy"},
				Message:          "Insufficient data to determine compliance",
			},
			expected: PolicyComplianceResult{
				PolicyName:       "UnknownPolicy",
				ComplianceStatus: configServiceTypes.ComplianceTypeInsufficientData,
				Reasons:          []string{"Unable to analyze policy"},
				Message:          "Insufficient data to determine compliance",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.result)
			assert.Equal(t, tt.expected.PolicyName, tt.result.PolicyName)
			assert.Equal(t, tt.expected.ComplianceStatus, tt.result.ComplianceStatus)
			assert.Equal(t, tt.expected.Reasons, tt.result.Reasons)
			assert.Equal(t, tt.expected.Message, tt.result.Message)
		})
	}
}

func TestPolicyScanResult(t *testing.T) {
	testTime := time.Now()
	
	tests := []struct {
		name     string
		result   PolicyScanResult
		expected PolicyScanResult
	}{
		{
			name: "complete policy scan result",
			result: PolicyScanResult{
				PrincipalArn:     "arn:aws:iam::123456789012:role/TestRole",
				PrincipalType:    "AWS::IAM::Role",
				ComplianceStatus: configServiceTypes.ComplianceTypeCompliant,
				PolicyResults: []PolicyComplianceResult{
					{
						PolicyName:       "Policy1",
						ComplianceStatus: configServiceTypes.ComplianceTypeCompliant,
						Reasons:          []string{},
						Message:          "Compliant",
					},
				},
				Annotation: "All policies are compliant",
				Timestamp:  testTime,
			},
			expected: PolicyScanResult{
				PrincipalArn:     "arn:aws:iam::123456789012:role/TestRole",
				PrincipalType:    "AWS::IAM::Role",
				ComplianceStatus: configServiceTypes.ComplianceTypeCompliant,
				PolicyResults: []PolicyComplianceResult{
					{
						PolicyName:       "Policy1",
						ComplianceStatus: configServiceTypes.ComplianceTypeCompliant,
						Reasons:          []string{},
						Message:          "Compliant",
					},
				},
				Annotation: "All policies are compliant",
				Timestamp:  testTime,
			},
		},
		{
			name: "empty policy scan result",
			result: PolicyScanResult{
				PrincipalArn:     "",
				PrincipalType:    "",
				ComplianceStatus: configServiceTypes.ComplianceTypeInsufficientData,
				PolicyResults:    []PolicyComplianceResult{},
				Annotation:       "",
				Timestamp:        time.Time{},
			},
			expected: PolicyScanResult{
				PrincipalArn:     "",
				PrincipalType:    "",
				ComplianceStatus: configServiceTypes.ComplianceTypeInsufficientData,
				PolicyResults:    []PolicyComplianceResult{},
				Annotation:       "",
				Timestamp:        time.Time{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.result)
			assert.Equal(t, tt.expected.PrincipalArn, tt.result.PrincipalArn)
			assert.Equal(t, tt.expected.PrincipalType, tt.result.PrincipalType)
			assert.Equal(t, tt.expected.ComplianceStatus, tt.result.ComplianceStatus)
			assert.Equal(t, tt.expected.PolicyResults, tt.result.PolicyResults)
			assert.Equal(t, tt.expected.Annotation, tt.result.Annotation)
			assert.Equal(t, tt.expected.Timestamp, tt.result.Timestamp)
		})
	}
}

func TestOrphanPolicyRequest(t *testing.T) {
	tests := []struct {
		name     string
		request  OrphanPolicyRequest
		expected OrphanPolicyRequest
	}{
		{
			name: "complete orphan policy request",
			request: OrphanPolicyRequest{
				PolicyArn:  "arn:aws:iam::123456789012:policy/TestPolicy",
				PolicyName: "TestPolicy",
				AccountID:  "123456789012",
			},
			expected: OrphanPolicyRequest{
				PolicyArn:  "arn:aws:iam::123456789012:policy/TestPolicy",
				PolicyName: "TestPolicy",
				AccountID:  "123456789012",
			},
		},
		{
			name: "empty orphan policy request",
			request: OrphanPolicyRequest{
				PolicyArn:  "",
				PolicyName: "",
				AccountID:  "",
			},
			expected: OrphanPolicyRequest{
				PolicyArn:  "",
				PolicyName: "",
				AccountID:  "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.request)
			assert.Equal(t, tt.expected.PolicyArn, tt.request.PolicyArn)
			assert.Equal(t, tt.expected.PolicyName, tt.request.PolicyName)
			assert.Equal(t, tt.expected.AccountID, tt.request.AccountID)
		})
	}
}

func TestOrphanPolicyResult(t *testing.T) {
	testTime := time.Now()
	
	tests := []struct {
		name     string
		result   OrphanPolicyResult
		expected OrphanPolicyResult
	}{
		{
			name: "orphan policy found",
			result: OrphanPolicyResult{
				PolicyArn:        "arn:aws:iam::123456789012:policy/OrphanPolicy",
				PolicyName:       "OrphanPolicy",
				ComplianceStatus: configServiceTypes.ComplianceTypeNonCompliant,
				Annotation:       "Policy is not attached to any IAM principal",
				Timestamp:        testTime,
			},
			expected: OrphanPolicyResult{
				PolicyArn:        "arn:aws:iam::123456789012:policy/OrphanPolicy",
				PolicyName:       "OrphanPolicy",
				ComplianceStatus: configServiceTypes.ComplianceTypeNonCompliant,
				Annotation:       "Policy is not attached to any IAM principal",
				Timestamp:        testTime,
			},
		},
		{
			name: "policy is attached",
			result: OrphanPolicyResult{
				PolicyArn:        "arn:aws:iam::123456789012:policy/AttachedPolicy",
				PolicyName:       "AttachedPolicy",
				ComplianceStatus: configServiceTypes.ComplianceTypeCompliant,
				Annotation:       "Policy is attached to IAM principals",
				Timestamp:        testTime,
			},
			expected: OrphanPolicyResult{
				PolicyArn:        "arn:aws:iam::123456789012:policy/AttachedPolicy",
				PolicyName:       "AttachedPolicy",
				ComplianceStatus: configServiceTypes.ComplianceTypeCompliant,
				Annotation:       "Policy is attached to IAM principals",
				Timestamp:        testTime,
			},
		},
		{
			name: "empty orphan policy result",
			result: OrphanPolicyResult{
				PolicyArn:        "",
				PolicyName:       "",
				ComplianceStatus: configServiceTypes.ComplianceTypeInsufficientData,
				Annotation:       "",
				Timestamp:        time.Time{},
			},
			expected: OrphanPolicyResult{
				PolicyArn:        "",
				PolicyName:       "",
				ComplianceStatus: configServiceTypes.ComplianceTypeInsufficientData,
				Annotation:       "",
				Timestamp:        time.Time{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.result)
			assert.Equal(t, tt.expected.PolicyArn, tt.result.PolicyArn)
			assert.Equal(t, tt.expected.PolicyName, tt.result.PolicyName)
			assert.Equal(t, tt.expected.ComplianceStatus, tt.result.ComplianceStatus)
			assert.Equal(t, tt.expected.Annotation, tt.result.Annotation)
			assert.Equal(t, tt.expected.Timestamp, tt.result.Timestamp)
		})
	}
}