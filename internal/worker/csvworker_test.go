package worker

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/mock"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/sdkapimgr"
	"github.com/stretchr/testify/assert"
)

func TestNewCsvWorker(t *testing.T) {
	assertion := assert.New(t)

	var (
		invalidAwsAccountId = "invalid-aws-account-id"
		validAwsAccountId   = "012345678910"
		validWorkerConfig   = WorkerConfig{
			Ctx:          context.Background(),
			Id:           "testCsvWorker",
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
		csvWorkerTests = []struct {
			name               string
			input              CsvWorkerConfig
			expectedValidValue bool
			expectedError      error
		}{
			{
				"valid csv worker config", CsvWorkerConfig{
					AccountId:    validAwsAccountId,
					WorkerConfig: validWorkerConfig,
					OutputConfig: validOutputConfig,
				}, true, nil,
			},
			{
				"invalid account id", CsvWorkerConfig{
					AccountId:    invalidAwsAccountId,
					WorkerConfig: validWorkerConfig,
					OutputConfig: validOutputConfig,
				}, false, errors.New("invalid account id"),
			},
			{
				"invalid worker config", CsvWorkerConfig{
					AccountId:    validAwsAccountId,
					WorkerConfig: WorkerConfig{},
					OutputConfig: validOutputConfig,
				}, false, errors.New("invalid worker config"),
			},
			{
				"invalid output config - write to s3 & local set to false", CsvWorkerConfig{
					AccountId:    validAwsAccountId,
					WorkerConfig: validWorkerConfig,
					OutputConfig: OutputConfiguration{
						Headers:    []string{"test"},
						Filename:   "test.csv",
						Prefix:     "testPrefix",
						BucketName: "XXXXXXXXXXX",
						WriteLocal: false,
						Writes3:    false,
					},
				}, false, errors.New("invalid output config"),
			},
			{
				"invalid output config - empty bucketname", CsvWorkerConfig{
					AccountId:    validAwsAccountId,
					WorkerConfig: validWorkerConfig,
					OutputConfig: OutputConfiguration{
						Headers:    []string{"test"},
						Filename:   "test.csv",
						Prefix:     "testPrefix",
						BucketName: "",
						WriteLocal: true,
						Writes3:    true,
					},
				}, false, errors.New("invalid output config"),
			},
			{
				"invalid output config - empty headers", CsvWorkerConfig{
					AccountId:    validAwsAccountId,
					WorkerConfig: validWorkerConfig,
					OutputConfig: OutputConfiguration{
						Headers:    []string{},
						Filename:   "test.csv",
						BucketName: "XXXXXXXXXX",
						WriteLocal: true,
						Writes3:    true,
					},
				}, false, errors.New("invalid output config"),
			},
			{
				"invalid output config - empty filename", CsvWorkerConfig{
					AccountId:    validAwsAccountId,
					WorkerConfig: validWorkerConfig,
					OutputConfig: OutputConfiguration{
						Headers:    []string{"test"},
						Filename:   "",
						Prefix:     "testPrefix",
						BucketName: "XXXXXXXXXX",
						WriteLocal: true,
						Writes3:    true,
					},
				}, false, errors.New("invalid output config"),
			},
		}
	)

	// add mock s3 api to sdk client mgr interface
	err := validWorkerConfig.SdkClientMgr.SetApi(validAwsAccountId, sdkapimgr.S3Service, &mock.MockS3Api{})
	assertion.NoError(err)

	// loop through test cases and create new csv worker for each test case
	for _, test := range csvWorkerTests {
		t.Run(test.name, func(t *testing.T) {
			csvWorker, err := NewCSVWorker(test.input)
			if test.expectedValidValue {
				assertion.NoError(err)
				assertion.NotNil(csvWorker)
			} else {
				assertion.Error(err)
				assertion.Contains(err.Error(), test.expectedError.Error())
			}
		})
	}

	close(validWorkerConfig.RequestChan) // close request channel to end worker loop
	validWorkerConfig.Wg.Wait()          // wait for worker to complete
	close(validWorkerConfig.ErrorChan)   // close error channel

}

func TestCsvWorkerRun(t *testing.T) {
	assertion := assert.New(t)

	var (
		validAwsAccountId    = "012345678910"
		validCsvWorkerConfig = CsvWorkerConfig{
			AccountId: validAwsAccountId,
			WorkerConfig: WorkerConfig{
				Ctx:          context.Background(),
				Id:           "testCsvWorker",
				Wg:           new(sync.WaitGroup),
				RequestChan:  make(chan interface{}, 1),
				ErrorChan:    make(chan error, 1),
				SdkClientMgr: sdkapimgr.NewAwsApiMgr(),
			},
			OutputConfig: OutputConfiguration{
				Headers:    []string{"test"},
				Prefix:     "testPrefix",
				Filename:   "test.csv",
				BucketName: "XXXXXXXXXXX",
				WriteLocal: true,
				Writes3:    true,
			},
		}
		csvWorkerTests = []struct {
			name            string
			input           CsvWorkerRequest
			expectedRecords [][]string
		}{
			{"single record", CsvWorkerRequest{
				CsvRecord: []string{"test record"},
			}, [][]string{
				{"test record"},
			}},
		}
	)

	validCsvWorker, err := NewCSVWorker(validCsvWorkerConfig)
	assertion.NoError(err)
	assertion.NotNil(validCsvWorker)

	// add mock s3 api to sdk client mgr interface
	err = validCsvWorkerConfig.WorkerConfig.SdkClientMgr.SetApi(validAwsAccountId, sdkapimgr.S3Service, &mock.MockS3Api{})
	assertion.NoError(err)

	for _, test := range csvWorkerTests {
		validCsvWorkerConfig.WorkerConfig.RequestChan <- test.input
	}

	close(validCsvWorkerConfig.WorkerConfig.RequestChan) // close request channel to end worker loop
	validCsvWorkerConfig.WorkerConfig.Wg.Wait()          // wait for worker to complete
	close(validCsvWorkerConfig.WorkerConfig.ErrorChan)   // close error channel

	assertion.Equal(len(csvWorkerTests), len(validCsvWorker.records))
	for i, test := range csvWorkerTests {
		assertion.Equal(test.expectedRecords[i], validCsvWorker.records[i])
	}

	// clean up files
	os.Remove(validCsvWorker.outputConfig.Filename)
}
