package worker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/mock"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/sdkapimgr"
	"github.com/stretchr/testify/assert"
)

func TestOrphanPolicyWorker(t *testing.T) {
	assertion := assert.New(t)

	var (
		eventTime               = time.Now()                // create event time
		configEvaluationChannel = make(chan interface{}, 1) // create config evaluation channel
		validWorkerConfig       = WorkerConfig{
			Ctx:          context.Background(),
			Id:           "orphan policy worker",
			Wg:           new(sync.WaitGroup),
			RequestChan:  make(chan interface{}, 1),
			ErrorChan:    make(chan error, 1),
			SdkClientMgr: sdkapimgr.NewAwsApiMgr(),
		}

		tests = []struct {
			name               string
			input              OrphanPolicyWorkerConfig
			expectedValidValue bool
			expectedError      error
		}{
			{"valid orphan policy worker", OrphanPolicyWorkerConfig{
				ConfigEvaluationChan: configEvaluationChannel,
				EventTime:            eventTime,
				WorkerConfig:         validWorkerConfig,
			}, true, nil},

			{"invalid worker config", OrphanPolicyWorkerConfig{
				ConfigEvaluationChan: configEvaluationChannel,
				EventTime:            eventTime,
				WorkerConfig:         WorkerConfig{},
			}, false, errors.New("invalid worker config")},

			{"missing config evaluation channel", OrphanPolicyWorkerConfig{
				ConfigEvaluationChan: nil,
				EventTime:            eventTime,
				WorkerConfig:         validWorkerConfig,
			}, false, errors.New("invalid orphan policy worker config")},

			{"missing event time", OrphanPolicyWorkerConfig{
				ConfigEvaluationChan: configEvaluationChannel,
				EventTime:            time.Time{},
				WorkerConfig:         validWorkerConfig,
			}, false, errors.New("invalid orphan policy worker config")},
		}
	)

	for _, test := range tests {
		worker, err := NewOrphanPolicyWorker(test.input)
		// if the expected valid value is true
		if test.expectedValidValue {
			assertion.NotNil(worker)                            // assert the worker is not nil
			assertion.NoError(err)                              // assert the error is nil
			assertion.True(worker.Worker.IsRequestHandlerSet()) // assert request handler is set
		} else {
			assertion.Nil(worker)                                       // assert the worker is nil
			assertion.Error(err)                                        // assert the error is not nil
			assertion.Contains(err.Error(), test.expectedError.Error()) // assert the error contains the expected error message
		}
	}

	close(validWorkerConfig.RequestChan) // close request channel
	validWorkerConfig.Wg.Wait()          // wait for worker to finish
	close(configEvaluationChannel)       // close config evaluation channel
	close(validWorkerConfig.ErrorChan)   // close error channel
}

func TestOrphanPolicyWorkerRequestHandler(t *testing.T) {
	assertion := assert.New(t)

	var (
		iamApi                  = &mock.MockIamApi{}        // create mock access analyzer api
		accountId               = "test-account-id"         // set test account id
		eventTime               = time.Now()                // create event time
		configEvaluationChannel = make(chan interface{}, 1) // create config evaluation channel
		validWorkerConfig       = WorkerConfig{
			Ctx:          context.Background(),
			Id:           "orphan policy worker",
			Wg:           new(sync.WaitGroup),
			RequestChan:  make(chan interface{}, 1),
			ErrorChan:    make(chan error, 1),
			SdkClientMgr: sdkapimgr.NewAwsApiMgr(),
		}
		requestHandlerTests = []struct {
			name   string
			input  OrphanPolicyWorkerRequest
			output []configServiceTypes.Evaluation
		}{
			{"valid request", OrphanPolicyWorkerRequest{
				AccountId: accountId,
				IamApi:    iamApi,
			}, []configServiceTypes.Evaluation{
				{
					ComplianceResourceId:   aws.String(mock.TestCompliantPolicyArn),
					ComplianceResourceType: aws.String("AWS::IAM::Policy"),
					ComplianceType:         "NON_COMPLIANT",
					OrderingTimestamp:      aws.Time(eventTime),
					Annotation:             aws.String("policy is orphaned"),
				},
				{
					ComplianceResourceId:   aws.String(mock.TestNonCompliantPolicyArn),
					ComplianceResourceType: aws.String("AWS::IAM::Policy"),
					ComplianceType:         "COMPLIANT",
					OrderingTimestamp:      aws.Time(eventTime),
					Annotation:             aws.String("policy is attached to"),
				},
			}},
		}
	)

	orphanPolicyWorker, err := NewOrphanPolicyWorker(OrphanPolicyWorkerConfig{
		ConfigEvaluationChan: configEvaluationChannel,
		EventTime:            eventTime,
		WorkerConfig:         validWorkerConfig,
	})
	assertion.NoError(err)               // assert the error is nil
	assertion.NotNil(orphanPolicyWorker) // assert the worker is not nil

	awsSDKClientMgr := validWorkerConfig.SdkClientMgr
	err = awsSDKClientMgr.SetApi(accountId, sdkapimgr.IamService, iamApi) // set mock access analyzer api to client map
	assertion.NoError(err)                                                // assert the error is nil

	// start go routine to process results from config evaluation channel
	testWg := new(sync.WaitGroup)
	batchEvaluations := []configServiceTypes.Evaluation{}
	testWg.Add(1)
	go func() {
		defer testWg.Done()
		for evaluation := range configEvaluationChannel {
			request := evaluation.(ConfigEvaluationWorkerRequest) // type assert to config evaluation
			batchEvaluations = append(batchEvaluations, request.ConfigEvaluation)
		}

		for _, tests := range requestHandlerTests {

			// compare first evaluation
			assertion.Equal(*tests.output[0].ComplianceResourceId, *batchEvaluations[0].ComplianceResourceId)
			assertion.Equal(*tests.output[0].ComplianceResourceType, *batchEvaluations[0].ComplianceResourceType)
			assertion.Equal(tests.output[0].ComplianceType, batchEvaluations[0].ComplianceType)
			assertion.Equal(*tests.output[0].OrderingTimestamp, *batchEvaluations[0].OrderingTimestamp)
			assertion.Contains(*batchEvaluations[0].Annotation, *tests.output[0].Annotation)

			// compare second evaluation
			assertion.Equal(*tests.output[1].ComplianceResourceId, *batchEvaluations[1].ComplianceResourceId)
			assertion.Equal(*tests.output[1].ComplianceResourceType, *batchEvaluations[1].ComplianceResourceType)
			assertion.Equal(tests.output[1].ComplianceType, batchEvaluations[1].ComplianceType)
			assertion.Equal(*tests.output[1].OrderingTimestamp, *batchEvaluations[1].OrderingTimestamp)
			assertion.Contains(*batchEvaluations[1].Annotation, *tests.output[1].Annotation)
		}
	}()

	// send requests to request channel
	for _, test := range requestHandlerTests {
		validWorkerConfig.RequestChan <- test.input
	}

	close(validWorkerConfig.RequestChan) // close request channel
	validWorkerConfig.Wg.Wait()          // wait for worker to finish
	close(configEvaluationChannel)       // close config evaluation channel
	close(validWorkerConfig.ErrorChan)   // close error channel
	testWg.Wait()                        // wait for test to finish
}
