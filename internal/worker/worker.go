package worker

import (
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	accessAnalyzerTypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
)

const (
	MaxPageSize       = 1000
	PrincipalTypeRole = "AWS::IAM::Role"
	PrincipalTypeUser = "AWS::IAM::User"
	DenyOnlyErrMsg    = "You must include at least one allow statement for analysis"
)

type PolicyScanResult struct {
	PrincipalArn     string
	PrincipalType    string
	ComplianceStatus configServiceTypes.ComplianceType
	Annotation       string
	Timestamp        time.Time
}

type OrphanPolicyResult struct {
	PolicyArn        string
	PolicyName       string
	ComplianceStatus configServiceTypes.ComplianceType
	Annotation       string
	Timestamp        time.Time
}

func convertReasonsToString(reasons []accessAnalyzerTypes.ReasonSummary) []string {
	var reasonsStrs []string
	for _, reason := range reasons {
		if description := aws.ToString(reason.Description); description != "" {
			reasonsStrs = append(reasonsStrs, description)
		}
	}
	return reasonsStrs
}

func extractAccountFromArn(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}