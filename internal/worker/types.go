package worker

import (
	"time"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
)

// Policy scan types
type PolicyScanRequest struct {
	PrincipalArn  string
	PrincipalType string
	PrincipalName string
	AccountID     string
}

type PolicyComplianceResult struct {
	PolicyName       string
	ComplianceStatus configServiceTypes.ComplianceType
	Reasons          []string
	Message          string
}

type PolicyScanResult struct {
	PrincipalArn     string
	PrincipalType    string
	ComplianceStatus configServiceTypes.ComplianceType
	PolicyResults    []PolicyComplianceResult
	Annotation       string
	Timestamp        time.Time
}

// Orphan policy types
type OrphanPolicyRequest struct {
	PolicyArn  string
	PolicyName string
	AccountID  string
}

type OrphanPolicyResult struct {
	PolicyArn        string
	PolicyName       string
	ComplianceStatus configServiceTypes.ComplianceType
	Annotation       string
	Timestamp        time.Time
}