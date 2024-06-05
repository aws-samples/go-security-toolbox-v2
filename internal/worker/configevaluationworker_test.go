package worker

import (
	"context"
	"encoding/csv"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/mock"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/sdkapimgr"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/shared"
	"github.com/stretchr/testify/assert"
)

func TestNewConfigEvaluationWorker(t *testing.T) {
	assertion := assert.New(t)

	var (
		invalidAwsAccountId = "invald-aws-account-id"
		validAwsAccountId   = "012345678910"
		validWorkerConfig   = WorkerConfig{
			Ctx:          context.Background(),
			Id:           "configEvaluationWorker",
			Wg:           new(sync.WaitGroup),
			RequestChan:  make(chan interface{}, 1),
			ErrorChan:    make(chan error, 1),
			SdkClientMgr: sdkapimgr.NewAwsApiMgr(),
		}
		validOutputConfig = OutputConfiguration{
			Headers:    []string{"test"},
			Filename:   "test.csv",
			Prefix:     "testPrefix",
			BucketName: "test-bucket",
			WriteLocal: true,
			Writes3:    true,
		}
		validCsvWorkerConfig = CsvWorkerConfig{
			AccountId:    validAwsAccountId,
			WorkerConfig: validWorkerConfig,
			OutputConfig: validOutputConfig,
		}
		configEvaluationWorkerTests = []struct {
			name               string
			input              ConfigEvaluationWorkerConfig
			expectedValidValue bool
			expectedError      error
		}{
			{"invalid worker config", ConfigEvaluationWorkerConfig{
				AccountId:        validAwsAccountId,
				ResultToken:      "",
				TestMode:         true,
				CsvWorkerEnabled: true,
				CsvWorkerConfig:  validCsvWorkerConfig,
				WorkerConfig:     WorkerConfig{},
			}, false, errors.New("invalid worker config")},

			{
				"invalid csv worker config", ConfigEvaluationWorkerConfig{
					AccountId:        validAwsAccountId,
					ResultToken:      "",
					TestMode:         true,
					CsvWorkerEnabled: true,
					CsvWorkerConfig:  CsvWorkerConfig{},
					WorkerConfig:     validWorkerConfig,
				}, false, errors.New("invalid csv worker config")},
			{
				"invalid aws account id", ConfigEvaluationWorkerConfig{
					AccountId:        invalidAwsAccountId,
					ResultToken:      "",
					TestMode:         true,
					CsvWorkerEnabled: true,
					CsvWorkerConfig:  validCsvWorkerConfig,
					WorkerConfig:     validWorkerConfig,
				}, false, errors.New("invalid aws account id")},
			{
				"invalid result token", ConfigEvaluationWorkerConfig{
					AccountId:        validAwsAccountId,
					ResultToken:      "",
					TestMode:         false,
					CsvWorkerEnabled: true,
					CsvWorkerConfig:  validCsvWorkerConfig,
					WorkerConfig:     validWorkerConfig,
				}, false, errors.New("invalid result token")},
			{
				"valid config", ConfigEvaluationWorkerConfig{
					AccountId:        validAwsAccountId,
					ResultToken:      "valid_token",
					TestMode:         false,
					CsvWorkerEnabled: true,
					CsvWorkerConfig:  validCsvWorkerConfig,
					WorkerConfig:     validWorkerConfig,
				}, true, nil},
		}
	)

	for _, test := range configEvaluationWorkerTests {
		t.Run(test.name, func(t *testing.T) {
			worker, err := NewConfigEvaluationWorker(test.input)
			if test.expectedValidValue {
				assertion.NotNil(worker)
				assertion.NoError(err)
				assertion.True(worker.Worker.IsRequestHandlerSet())
				assertion.True(worker.Worker.IsFinalizerSet())
			} else {
				assertion.Nil(worker)
				assertion.Error(err)
				assertion.Contains(err.Error(), test.expectedError.Error())
			}
		})
	}

}

func TestHandleConfigEvaluationRequest(t *testing.T) {
	assertion := assert.New(t)

	var (
		eventTime                    = time.Now()
		validResourceId              = "testResourceId"
		testAnnotation               = "testAnnotation"
		validAwsAccountId            = "012345678910"
		complianceResourceType       = shared.AwsIamPolicy
		complianceType               = configServiceTypes.ComplianceTypeCompliant
		configWorkerOutputFilename   = "configworkeroutput.csv"
		configWorkerOutputFileHeader = []string{"ID", "Compliance Type", "Status", "Annotation", "Ordering Timestamp"}
		validWorkerConfig            = WorkerConfig{
			Ctx:          context.Background(),
			Id:           "configEvaluationWorker",
			Wg:           new(sync.WaitGroup),
			RequestChan:  make(chan interface{}, 1),
			ErrorChan:    make(chan error, 1),
			SdkClientMgr: sdkapimgr.NewAwsApiMgr(),
		}
		validOutputConfig = OutputConfiguration{
			Headers:    configWorkerOutputFileHeader,
			Filename:   configWorkerOutputFilename,
			Prefix:     "testPrefix",
			BucketName: "XXXXXXXXXXX",
			WriteLocal: true,
			Writes3:    true,
		}
		validCsvWorkerConfig = CsvWorkerConfig{
			AccountId: validAwsAccountId,
			WorkerConfig: WorkerConfig{
				Ctx:          context.Background(),
				Id:           "config evaluation csv worker",
				Wg:           new(sync.WaitGroup),
				RequestChan:  make(chan interface{}, 1),
				ErrorChan:    validWorkerConfig.ErrorChan,
				SdkClientMgr: validWorkerConfig.SdkClientMgr,
			},
			OutputConfig: validOutputConfig,
		}
		validConfigEvaluationWorkerConfig = ConfigEvaluationWorkerConfig{
			AccountId:        validAwsAccountId,
			ResultToken:      "valid_token",
			TestMode:         false,
			CsvWorkerEnabled: true,
			CsvWorkerConfig:  validCsvWorkerConfig,
			WorkerConfig:     validWorkerConfig,
		}
		configEvaluationWorkerTests = []struct {
			name               string
			evaluation         ConfigEvaluationWorkerRequest
			evaluationCount    int
			expectedHeader     []string
			expectedEvaluation [][]string
		}{
			{
				"valid request", ConfigEvaluationWorkerRequest{
					ConfigEvaluation: configServiceTypes.Evaluation{
						ComplianceResourceId:   aws.String(validResourceId),
						ComplianceResourceType: aws.String(complianceResourceType),
						ComplianceType:         complianceType,
						OrderingTimestamp:      aws.Time(eventTime),
						Annotation:             aws.String(testAnnotation),
					},
				}, 200, configWorkerOutputFileHeader, [][]string{
					{validResourceId, shared.AwsIamPolicy, string(configServiceTypes.ComplianceTypeCompliant), testAnnotation, eventTime.Format(time.RFC3339)},
				},
			},
		}
	)

	configEvaluationWorker, err := NewConfigEvaluationWorker(validConfigEvaluationWorkerConfig)
	assertion.NoError(err)
	assertion.NotNil(configEvaluationWorker)
	assertion.True(configEvaluationWorker.Worker.IsRequestHandlerSet())
	assertion.True(configEvaluationWorker.Worker.IsFinalizerSet())

	// add mock config service api to sdk client manager
	err = validWorkerConfig.SdkClientMgr.SetApi(validAwsAccountId, sdkapimgr.ConfigService, &mock.MockConfigService{})
	assertion.NoError(err)
	// add mock s3 api to sdk client manager
	err = validWorkerConfig.SdkClientMgr.SetApi(validAwsAccountId, sdkapimgr.S3Service, &mock.MockS3Api{})
	assertion.NoError(err)

	for _, test := range configEvaluationWorkerTests {
		t.Run(test.name, func(t *testing.T) {
			// create config evaluations based on evaluation count
			batchEvaluations := make([]configServiceTypes.Evaluation, 0)
			for i := 0; i < test.evaluationCount; i++ {
				batchEvaluations = append(batchEvaluations, test.evaluation.ConfigEvaluation)
			}
			// send config evaluations to worker
			for _, evaluation := range batchEvaluations {
				validWorkerConfig.RequestChan <- ConfigEvaluationWorkerRequest{
					ConfigEvaluation: configServiceTypes.Evaluation{
						ComplianceResourceId:   evaluation.ComplianceResourceId,
						ComplianceResourceType: evaluation.ComplianceResourceType,
						ComplianceType:         evaluation.ComplianceType,
						OrderingTimestamp:      evaluation.OrderingTimestamp,
						Annotation:             evaluation.Annotation,
					},
				}
			}
			close(validWorkerConfig.RequestChan) // close request channel
			validWorkerConfig.Wg.Wait()          // wait for worker to complete

			// read csv file and validate count and contents
			csvFile, err := os.Open(configWorkerOutputFilename)
			assertion.NoError(err)
			assertion.NotNil(csvFile)

			defer csvFile.Close()

			reader := csv.NewReader(csvFile)
			assertion.NotNil(reader)
			records, err := reader.ReadAll()
			assertion.NoError(err)
			assertion.NotNil(records)
			assertion.Equal(test.evaluationCount, len(records)-1) // validate evaluation count

			for i, record := range records {
				// check header first
				if i == 0 {
					assertion.Equal(test.expectedHeader, record)
					continue
				}
				// compare remaining evaluations to expected record
				assertion.Equal(test.expectedEvaluation[0][0], record[0])
				assertion.Equal(test.expectedEvaluation[0][1], record[1])
				assertion.Equal(test.expectedEvaluation[0][2], record[2])
				assertion.Equal(test.expectedEvaluation[0][3], record[3])
				assertion.Equal(test.expectedEvaluation[0][4], record[4])
			}
		})
	}
	// clean up the files
	os.Remove(configWorkerOutputFilename)
	close(validWorkerConfig.ErrorChan) // close error channel
}
