package worker

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	accessAnalyzerTypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"

	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/cache"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/mock"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/sdkapimgr"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/shared"
	"github.com/stretchr/testify/assert"
)

var (
	userIamIdentity = &_IamIdentity{
		Arn:          mock.TestUserArn,
		Name:         mock.TestUserName,
		IdentityType: shared.AwsIamUser,
	}
	errorUserIamIdentity = &_IamIdentity{
		Arn:          mock.TestErrorUserArn,
		Name:         mock.TestErrorPolicyName,
		IdentityType: shared.AwsIamUser,
	}
	userWithErrorPolicyIamIdentity = &_IamIdentity{
		Arn:          mock.TestUserWithErrorPolicyArn,
		Name:         mock.TestUserWithErrorPolicyName,
		IdentityType: shared.AwsIamUser,
	}
	roleIamIdentity = &_IamIdentity{
		Arn:          mock.TestRoleArn,
		Name:         mock.TestRoleName,
		IdentityType: shared.AwsIamRole,
	}
	errorRoleIamIdentity = &_IamIdentity{
		Arn:          mock.TestErrorRoleArn,
		Name:         mock.TestErrorRoleName,
		IdentityType: shared.AwsIamRole,
	}
	roleWithErrorPolicyIamIdentity = &_IamIdentity{
		Arn:          mock.TestRoleWithErrorPolicyArn,
		Name:         mock.TestRoleWithErrorPolicyName,
		IdentityType: shared.AwsIamRole,
	}
)

func TestNewCustomPolicyScanWorker(t *testing.T) {
	var (
		restrictedActions     = []string{"s3:GetObject", "s3:PutObject"}
		configEvaluationsChan = make(chan interface{}, 1)
		semaphoreChan         = make(chan chan interface{}, 1)
		eventTime             = time.Now()
		validWorkerConfig     = WorkerConfig{
			Ctx:          context.Background(),
			Id:           "custom policy worker",
			Wg:           new(sync.WaitGroup),
			RequestChan:  make(chan interface{}, 1),
			ErrorChan:    make(chan error, 1),
			SdkClientMgr: sdkapimgr.NewAwsApiMgr(),
		}
		customPolicyScanTests = []struct {
			name               string
			input              CustomPolicyScanWorkerConfig
			expectedValueValue bool
		}{
			{"valid worker", CustomPolicyScanWorkerConfig{
				RestrictedActions:    restrictedActions,
				ConfigEvaluationChan: configEvaluationsChan,
				SemaphoreChan:        semaphoreChan,
				EventTime:            eventTime,
				WorkerConfig:         validWorkerConfig,
			}, true,
			},
			{
				"nil check", CustomPolicyScanWorkerConfig{
					RestrictedActions:    nil,
					ConfigEvaluationChan: configEvaluationsChan,
					SemaphoreChan:        semaphoreChan,
					EventTime:            eventTime,
					WorkerConfig:         validWorkerConfig,
				}, false,
			},
			{
				"invalid worker config", CustomPolicyScanWorkerConfig{
					RestrictedActions:    restrictedActions,
					ConfigEvaluationChan: configEvaluationsChan,
					SemaphoreChan:        semaphoreChan,
					EventTime:            eventTime,
					WorkerConfig:         WorkerConfig{},
				}, false,
			},
		}
	)

	for _, test := range customPolicyScanTests {
		t.Run(test.name, func(t *testing.T) {
			assertion := assert.New(t)

			worker, err := NewCustomPolicyScanWorker(test.input)
			// check if valid value is expected
			if test.expectedValueValue {
				assertion.NotNil(worker)
				assertion.NoError(err)
			} else {
				assertion.Nil(worker)
				assertion.Error(err)
			}
		})
	}
}

func TestNewComplianceResult(t *testing.T) {

	var (
		complianceType  = configServiceTypes.ComplianceTypeCompliant
		testDescription = "test description"
		testMessage     = "test message"
		testPolicyName  = "test policy name"
		testResourceArn = "test resource arn"
		testReasons     = []accessAnalyzerTypes.ReasonSummary{
			{
				Description: aws.String(testDescription),
			},
		}
		complianceResultTests = []struct {
			name               string
			input              complianceResultInput
			expectedOutput     CustomPolicyScanResult
			expectedValidValue bool
			expectedError      error
		}{
			{
				"valid compliance result", complianceResultInput{
					compliance:  complianceType,
					reasons:     testReasons,
					message:     testMessage,
					policyName:  testPolicyName,
					resourceArn: testResourceArn,
				}, CustomPolicyScanResult{
					Compliance:         complianceType,
					Reasons:            []string{*testReasons[0].Description},
					Message:            testMessage,
					PolicyDocumentName: testPolicyName,
					ResourceArn:        testResourceArn,
				}, true, nil,
			},
			{
				"invalid compliance type", complianceResultInput{
					compliance:  "",
					reasons:     testReasons,
					message:     testMessage,
					policyName:  testPolicyName,
					resourceArn: testResourceArn,
				}, CustomPolicyScanResult{}, false, errors.New("cannot create compliance result without compliance type"),
			},
			{
				"invalid resource arn", complianceResultInput{
					compliance:  complianceType,
					reasons:     testReasons,
					message:     testMessage,
					policyName:  testPolicyName,
					resourceArn: "",
				}, CustomPolicyScanResult{}, false, errors.New("cannot create compliance result without resource arn"),
			},
		}
	)

	for _, test := range complianceResultTests {
		t.Run(test.name, func(t *testing.T) {
			assertion := assert.New(t)

			result, err := newCustomPolicyScanResult(test.input)
			if test.expectedValidValue {
				assertion.NoError(err)
				assertion.Equal(test.expectedOutput.Compliance, result.Compliance)
				assertion.Equal(test.expectedOutput.Reasons, result.Reasons)
				assertion.Equal(test.expectedOutput.Message, result.Message)
				assertion.Equal(test.expectedOutput.PolicyDocumentName, result.PolicyDocumentName)
				assertion.Equal(test.expectedOutput.ResourceArn, result.ResourceArn)
			} else {
				assertion.Error(err)
				assertion.Equal(test.expectedError.Error(), err.Error())
			}
		})
	}
}

func TestHandlecustomPolicyScanError(t *testing.T) {
	var (
		errorChan               = make(chan error, 1)
		customPolicyResultsChan = make(chan interface{}, 1)
		resultsCache            = cache.NewCustomPolicyScanResultsCache()
		resultsMsg              = "test msg"
		resultsResourceArn      = "test reasource arn"
		resultsReasons          = []accessAnalyzerTypes.ReasonSummary{
			{
				Description: aws.String("test description"),
			},
		}
		resultsCompliance      = configServiceTypes.ComplianceType("COMPLIANT")
		resultsPolicyName      = "test policy name"
		complianceResultsInput = complianceResultInput{
			compliance:  resultsCompliance,
			reasons:     resultsReasons,
			message:     resultsMsg,
			resourceArn: resultsResourceArn,
			policyName:  resultsPolicyName,
		}
		customPolicyScanResult = CustomPolicyScanResult{
			Compliance:         resultsCompliance,
			Reasons:            []string{*resultsReasons[0].Description},
			Message:            resultsMsg,
			PolicyDocumentName: resultsPolicyName,
			ResourceArn:        resultsResourceArn,
		}
		tests = []struct {
			name                                   string
			input                                  handleCustomPolicyscanErrorInput
			expectError                            bool
			err                                    error
			expectErrorChanValue                   bool
			expectCustomPolicyScanResultsChanValue bool
			customPolicyScanResult                 CustomPolicyScanResult
		}{
			{"invalid error - missing error channel", handleCustomPolicyscanErrorInput{
				errorChan:                   nil,
				customPolicyScanResultsChan: customPolicyResultsChan,
				cache:                       resultsCache,
				complianceResultInput:       complianceResultsInput,
			}, true, errors.New("empty error channel"), false, false, CustomPolicyScanResult{}},
			{"invalid error - missing custom policy scan results channel", handleCustomPolicyscanErrorInput{
				errorChan:                   errorChan,
				customPolicyScanResultsChan: nil,
				cache:                       resultsCache,
				complianceResultInput:       complianceResultsInput,
			}, true, errors.New("empty results channel"), false, false, CustomPolicyScanResult{}},
			{"valid error", handleCustomPolicyscanErrorInput{
				errorChan:                   errorChan,
				customPolicyScanResultsChan: customPolicyResultsChan,
				cache:                       resultsCache,
				complianceResultInput:       complianceResultsInput,
			}, false, nil, true, true, customPolicyScanResult},
		}
	)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertion := assert.New(t)

			var handler _CustomPolicyScanErrorHandler
			err := handler.Handle(test.input)
			if test.expectError {
				assertion.Error(err)
				assertion.Contains(err.Error(), test.err.Error())
			} else {
				assertion.NoError(err)
			}
			if test.expectErrorChanValue {
				errorChanValue := <-errorChan
				assertion.Error(errorChanValue)
			} else {
				assertion.Equal(0, len(errorChan))
			}
			if test.expectCustomPolicyScanResultsChanValue {
				customPolicyScanResultsChanValue := <-customPolicyResultsChan
				result := customPolicyScanResultsChanValue.(CustomPolicyScanResult)
				assertion.Equal(test.customPolicyScanResult.Compliance, result.Compliance)
				for index, reason := range test.customPolicyScanResult.Reasons {
					assertion.Equal(reason, result.Reasons[index])
				}
				assertion.Equal(test.customPolicyScanResult.Message, result.Message)
				assertion.Equal(test.customPolicyScanResult.PolicyDocumentName, result.PolicyDocumentName)
				assertion.Equal(test.customPolicyScanResult.ResourceArn, result.ResourceArn)
			}
		})
	}
}

func TestIsCompliant(t *testing.T) {
	var (
		ctx                = context.Background()
		accessAnalyzerApi  = &mock.MockAccessAnalyzerApi{}
		policyDocumentName = "test policy document name"
		resourceArn        = "test resource arn"
		restrictedActions  = []string{"s3:GetObject", "s3:PutObject"}
		tests              = []struct {
			name                         string
			input                        isCompliantInput
			expectCustomPolicyScanResult bool
			CustomPolicyScanResult       CustomPolicyScanResult
			expectError                  bool
			err                          error
		}{
			{
				"error - empty restricted actions", isCompliantInput{
					ctx:                  ctx,
					accessAnalyzerClient: accessAnalyzerApi,
					policyDocumentName:   policyDocumentName,
					resourceArn:          resourceArn,
					restrictedActions:    nil,
					policyDocument:       "xxx",
				}, false, CustomPolicyScanResult{}, true, errors.New("cannot be empty"),
			},
			{
				"error - empty policy document", isCompliantInput{
					ctx:                  ctx,
					accessAnalyzerClient: accessAnalyzerApi,
					policyDocumentName:   policyDocumentName,
					resourceArn:          resourceArn,
					restrictedActions:    restrictedActions,
					policyDocument:       "",
				}, false, CustomPolicyScanResult{}, true, errors.New("cannot be empty"),
			},
			{
				"error - empty policy document name", isCompliantInput{
					ctx:                  ctx,
					accessAnalyzerClient: accessAnalyzerApi,
					policyDocumentName:   "",
					resourceArn:          resourceArn,
					restrictedActions:    restrictedActions,
					policyDocument:       "xxx",
				}, false, CustomPolicyScanResult{}, true, errors.New("cannot be empty"),
			},
			{
				"error - empty resource arn", isCompliantInput{
					ctx:                  ctx,
					accessAnalyzerClient: accessAnalyzerApi,
					policyDocumentName:   policyDocumentName,
					resourceArn:          "",
					restrictedActions:    restrictedActions,
					policyDocument:       "xxx",
				}, false, CustomPolicyScanResult{}, true, errors.New("cannot be empty"),
			},
			{
				"valid - compliant policy", isCompliantInput{
					ctx:                  ctx,
					accessAnalyzerClient: accessAnalyzerApi,
					policyDocumentName:   policyDocumentName,
					resourceArn:          resourceArn,
					restrictedActions:    restrictedActions,
					policyDocument:       "COMPLIANT",
				}, true, CustomPolicyScanResult{
					Compliance:         configServiceTypes.ComplianceTypeCompliant,
					PolicyDocumentName: policyDocumentName,
					ResourceArn:        resourceArn,
					Reasons:            []string{"test description"},
					Message:            "test compliant",
				}, false, nil,
			},
			{
				"valid - non-compliant policy", isCompliantInput{
					ctx:                  ctx,
					accessAnalyzerClient: accessAnalyzerApi,
					policyDocumentName:   policyDocumentName,
					resourceArn:          resourceArn,
					restrictedActions:    restrictedActions,
					policyDocument:       "NON-COMPLIANT",
				}, true, CustomPolicyScanResult{
					Compliance:         configServiceTypes.ComplianceTypeNonCompliant,
					PolicyDocumentName: policyDocumentName,
					ResourceArn:        resourceArn,
					Reasons:            []string{"test description"},
					Message:            "test non-compliant",
				}, false, nil,
			},
			{
				"invalid - non-compliant deny only actions", isCompliantInput{
					ctx:                  ctx,
					accessAnalyzerClient: accessAnalyzerApi,
					policyDocumentName:   policyDocumentName,
					resourceArn:          resourceArn,
					restrictedActions:    restrictedActions,
					policyDocument:       "DENY-ONLY",
				}, true, CustomPolicyScanResult{
					Compliance:         configServiceTypes.ComplianceTypeCompliant,
					Reasons:            nil,
					Message:            "",
					PolicyDocumentName: policyDocumentName,
					ResourceArn:        resourceArn,
				}, false, nil,
			},
		}
	)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertion := assert.New(t)

			result, err := isCompliant(test.input)
			if test.expectError {
				assertion.Error(err)
				assertion.Contains(err.Error(), test.err.Error())
			}
			if test.expectCustomPolicyScanResult {
				assertion.Equal(test.CustomPolicyScanResult.Compliance, result.Compliance)
				assertion.Equal(test.CustomPolicyScanResult.PolicyDocumentName, result.PolicyDocumentName)
				assertion.Equal(test.CustomPolicyScanResult.ResourceArn, result.ResourceArn)
				for index, reason := range test.CustomPolicyScanResult.Reasons {
					assertion.Equal(reason, result.Reasons[index])
				}
				assertion.Equal(test.CustomPolicyScanResult.Message, result.Message)
			}
		})
	}
}

func TestNewIamIdentity(t *testing.T) {

	var (
		validArn            = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		invalidArn          = ""
		validName           = "test-iam-identity-name"
		invalidName         = ""
		validIdentityTypes  = []string{"user", "role"}
		invalidIdentityType = ""
		tests               = []struct {
			name                 string
			input                IamIdentityConfig
			expectedValidValue   bool
			expectedArn          string
			expectedName         string
			expectedIdentityType string
			expectedError        error
		}{
			{"valid iam identity - user", IamIdentityConfig{
				Arn:          validArn,
				IdentityType: validIdentityTypes[0],
				Name:         validName,
			}, true, validArn, validName, validIdentityTypes[0], nil},
			{"valid iam identity - role", IamIdentityConfig{
				Arn:          validArn,
				IdentityType: validIdentityTypes[1],
				Name:         validName,
			}, true, validArn, validName, validIdentityTypes[1], nil},
			{"invalid iam identity - empty arn", IamIdentityConfig{
				Arn:          invalidArn,
				IdentityType: validIdentityTypes[0],
				Name:         validName,
			}, false, "", "", "", errors.New("required field(s) are nil")},
			{"invalid iam identity - empty name", IamIdentityConfig{
				Arn:          validArn,
				IdentityType: validIdentityTypes[0],
				Name:         invalidName,
			}, false, "", "", "", errors.New("required field(s) are nil")},
			{"invalid iam identity - empty identity type", IamIdentityConfig{
				Arn:          validArn,
				IdentityType: invalidIdentityType,
				Name:         validName,
			}, false, "", "", "", errors.New("required field(s) are nil")},
		}
	)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertion := assert.New(t)

			result, err := NewIamIdentity(test.input)
			if test.expectedValidValue {
				assertion.NoError(err)
				assertion.Equal(test.expectedArn, result.GetIdentityArn())
				assertion.Equal(test.expectedIdentityType, result.GetIdentityType())
				assertion.Equal(test.expectedName, result.GetIdentityName())
			} else {
				assertion.Error(err)
				assertion.Contains(err.Error(), test.expectedError.Error())
			}
		})
	}
}

func TestCreateConfigEvaluation(t *testing.T) {

	var (
		validResourceId                = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		compliantMessage               = "test-compliant-message"
		compliantPolicyDocumentName    = "test-compliant-policy-document-name"
		nonCompliantReasons            = []string{"test-non-compliant-reasons"}
		nonCompliantReasonsString      = strings.Join(nonCompliantReasons, ",")
		expectedAnnotation             = strings.Join([]string{compliantMessage, nonCompliantReasonsString}, "\n")
		nonCompliantPolicyDocumentName = "test-non-compliant-policy-document-name"

		tests = []struct {
			name                     string
			input                    createConfigEvaluationInput
			expectedValidValue       bool
			expectedConfigEvaluation configServiceTypes.Evaluation
			expectedError            error
		}{
			{"valid config evaluation", createConfigEvaluationInput{
				results: []CustomPolicyScanResult{
					{
						Compliance:         configServiceTypes.ComplianceTypeCompliant,
						ResourceArn:        validResourceId,
						Message:            compliantMessage,
						PolicyDocumentName: compliantPolicyDocumentName,
						Reasons:            []string{""},
					},
					{
						Compliance:         configServiceTypes.ComplianceTypeNonCompliant,
						ResourceArn:        validResourceId,
						Reasons:            nonCompliantReasons,
						Message:            "",
						PolicyDocumentName: nonCompliantPolicyDocumentName,
					},
				},
				complianceResourceType: shared.AwsIamRole,
			}, true, configServiceTypes.Evaluation{
				ComplianceType:         configServiceTypes.ComplianceTypeNonCompliant,
				ComplianceResourceId:   aws.String(validResourceId),
				ComplianceResourceType: aws.String(shared.AwsIamRole),
				Annotation:             aws.String(expectedAnnotation),
			}, nil},
		}
	)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertion := assert.New(t)

			result, err := createConfigEvaluation(test.input)
			if test.expectedValidValue {
				assertion.NoError(err)
				assertion.Equal(test.expectedConfigEvaluation.ComplianceType, result.ComplianceType)
				assertion.Equal(*test.expectedConfigEvaluation.ComplianceResourceId, *result.ComplianceResourceId)
				assertion.Equal(*test.expectedConfigEvaluation.ComplianceResourceType, *result.ComplianceResourceType)
				assertion.Equal(*test.expectedConfigEvaluation.Annotation, *result.Annotation)
			} else {
				assertion.Error(err)
				assertion.Contains(err.Error(), test.expectedError.Error())
			}
		})
	}
}
