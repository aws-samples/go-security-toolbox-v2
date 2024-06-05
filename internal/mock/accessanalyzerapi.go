package mock

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/shared"
)

var (
	TestCompliantPolicyDocument    string = "COMPLIANT"
	TestCompliantPolicyMessage     string = "test compliant"
	TestCompliantPolicyDescription string = "test description"

	TestNonCompliantPolicyDocument    string = "NON-COMPLIANT"
	TestNonCompliantPolicyMessage     string = "test non-compliant"
	TestNonCompliantPolicyDescription string = "test description"

	TestDenyOnlyPolicyDocument    string = "DENY-ONLY"
	TestDenyOnlyPolicyMessage     string = "test deny-only"
	TestDenyOnlyPolicyDescription string = shared.DenyOnlyErrMsg

	TestErrorPolicyDocument string = "test-error-policy-document"
	TestErrorPolicyMessage  string = "test error message"
	TestErrorPolicyReason   string = "test error reason"
)

type MockAccessAnalyzerApi struct {
}

// check access not granted
func (m *MockAccessAnalyzerApi) CheckAccessNotGranted(ctx context.Context, params *accessanalyzer.CheckAccessNotGrantedInput, optFns ...func(*accessanalyzer.Options)) (*accessanalyzer.CheckAccessNotGrantedOutput, error) {
	if *params.PolicyDocument == TestCompliantPolicyDocument {
		return &accessanalyzer.CheckAccessNotGrantedOutput{
			Message: aws.String(TestCompliantPolicyMessage),
			Reasons: []types.ReasonSummary{
				{
					Description: aws.String(TestCompliantPolicyDescription),
				},
			},
			Result: types.CheckAccessNotGrantedResultPass,
		}, nil
	} else if *params.PolicyDocument == TestNonCompliantPolicyDocument {
		return &accessanalyzer.CheckAccessNotGrantedOutput{
			Message: aws.String(TestNonCompliantPolicyMessage),
			Reasons: []types.ReasonSummary{
				{
					Description: aws.String(TestNonCompliantPolicyDescription),
				},
			},
			Result: types.CheckAccessNotGrantedResultFail,
		}, nil
	} else if *params.PolicyDocument == TestDenyOnlyPolicyDocument {
		return &accessanalyzer.CheckAccessNotGrantedOutput{}, errors.New(shared.DenyOnlyErrMsg)
	} else {
		return nil, errors.New("check access not granted error")
	}
}
