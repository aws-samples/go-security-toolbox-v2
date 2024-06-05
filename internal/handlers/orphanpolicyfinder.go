package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/iamapi"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/s3api"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/sdkapimgr"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/shared"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/worker"
)

type _OrphanPolicyFinder struct {
	s3Api s3api.S3Api
}

type OrphanPolicyFinderEvent struct {
	ConfigEvent events.ConfigEvent
}

type OrphanPolicyFinderConfig struct {
	AWSAccounts []shared.AWSAccount `json:"awsAccounts"`
	TestMode    bool                `json:"testMode"`
	Prefix      string              `json:"prefix"`
}

func NewOrphanPolicyFinder(cfg aws.Config) (Handler, error) {
	opfHandler := &_OrphanPolicyFinder{
		s3Api: s3api.NewS3SDKClient(s3.NewFromConfig(cfg)),
	}
	return opfHandler, nil
}

func (opf *_OrphanPolicyFinder) Handle(ctx context.Context, params interface{}) error {
	event, ok := params.(OrphanPolicyFinderEvent)
	if !ok {
		return errors.New("type assertion failure. event is not type orphanpolicyfinder event")
	}

	// read read environment variables for config file location
	configBucketName := os.Getenv(shared.EnvBucketName)
	log.Printf("configBucketName: [%s]\n", configBucketName)
	configFileObjectKey := os.Getenv(shared.EnvConfigFileKey)
	log.Printf("config file object key : [%s]\n", configFileObjectKey)

	if configBucketName == "" || configFileObjectKey == "" {
		return errors.New("env vars not set")
	}

	// read config file from s3
	getObjectOutput, err := opf.s3Api.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(configBucketName),
		Key:    aws.String(configFileObjectKey),
	})
	// return errors
	if err != nil {
		return err
	}

	var config OrphanPolicyFinderConfig
	objectContent, err := io.ReadAll(getObjectOutput.Body)
	// return errors
	if err != nil {
		return err
	}
	log.Printf("config file content: [%s]\n", objectContent)

	err = json.Unmarshal(objectContent, &config)
	// return errors
	if err != nil {
		return err
	}
	log.Printf("config file unmarshalled : [%+v]\n", config)

	var (
		batchErrors               = make([]error, 0)
		errorChan                 = make(chan error, 1)
		errorCsvWorkerRequestChan = make(chan interface{}, 1)
		errorCsvWorkerErrorchan   = make(chan error, 1)
	)

	// load aws config
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion("us-east-1"),
		awsconfig.WithRetryMode(aws.RetryModeStandard),
		awsconfig.WithRetryMaxAttempts(3))
	// return errors
	if err != nil {
		return err
	}

	// initialize aws sdk client manager
	awsClientMgr, err := sdkapimgr.InitAwsClientMgr(sdkapimgr.SDKApiMgrConfig{
		Cfg:           cfg,
		MainAccountId: event.ConfigEvent.AccountID,
		AwsAccounts:   config.AWSAccounts,
	})
	// return errors
	if err != nil {
		return err
	}

	now := time.Now()
	year, month, day := now.Year(), now.Month(), now.Day()
	hour, minute, second := now.Hour(), now.Minute(), now.Second()
	timestampPrefix := fmt.Sprintf("year=%d/month=%02d/day=%02d/%02d"+"-%02d"+"-%02d-", year, month, day, hour, minute, second)

	// process errors from error channel
	errorCsvWorker, err := worker.NewCSVWorker(worker.CsvWorkerConfig{
		AccountId: event.ConfigEvent.AccountID,
		WorkerConfig: worker.WorkerConfig{
			Ctx:          ctx,
			Id:           "error csv worker",
			Wg:           new(sync.WaitGroup),
			RequestChan:  errorCsvWorkerRequestChan,
			ErrorChan:    errorCsvWorkerErrorchan,
			SdkClientMgr: awsClientMgr,
		},
		OutputConfig: worker.OutputConfiguration{
			Headers:    []string{"error"},
			Filename:   "errors/" + timestampPrefix + "errors.csv",
			Prefix:     config.Prefix,
			BucketName: configBucketName,
			WriteLocal: false,
			Writes3:    true,
		},
	})
	// return errors
	if err != nil {
		return err
	}

	// process errors from csv error worker
	errorCsvWorkerErrorWg := new(sync.WaitGroup)
	errorCsvWorkerErrorWg.Add(1)
	go func() {
		defer errorCsvWorkerErrorWg.Done()
		for err := range errorCsvWorkerErrorchan {
			log.Printf("error from error csv worker: [%s]\n", err)
			batchErrors = append(batchErrors, err)
		}
	}()

	errorWorkerWg := new(sync.WaitGroup)
	errorWorkerWg.Add(1)
	go func() {
		defer errorWorkerWg.Done()
		for err := range errorChan {
			log.Printf("error from main threads error channel: [%s]\n", err.Error())
			errorCsvWorkerRequestChan <- err.Error() // send error to error csv worker
		}
	}()

	// create config evaluation worker
	var (
		configEvaluationWorkerRequestChan    = make(chan interface{}, 1)
		configEvaluationWorkerCsvRequestChan = make(chan interface{}, 1)
	)

	configEvaluationWorker, err := worker.NewConfigEvaluationWorker(worker.ConfigEvaluationWorkerConfig{
		AccountId:        event.ConfigEvent.AccountID,
		ResultToken:      event.ConfigEvent.ResultToken,
		TestMode:         config.TestMode,
		CsvWorkerEnabled: true,
		CsvWorkerConfig: worker.CsvWorkerConfig{
			AccountId: event.ConfigEvent.AccountID,
			WorkerConfig: worker.WorkerConfig{
				Ctx:          ctx,
				Id:           "config evaluation csv worker",
				Wg:           new(sync.WaitGroup),
				RequestChan:  configEvaluationWorkerCsvRequestChan,
				ErrorChan:    errorChan,
				SdkClientMgr: awsClientMgr,
			},
			OutputConfig: worker.OutputConfiguration{
				Headers: []string{"Resource Id",
					"Resource Type",
					"Compliance Status",
					"Annotation",
					"Timestamp",
				},
				Filename:   "results/" + timestampPrefix + "results.csv",
				Prefix:     config.Prefix,
				BucketName: configBucketName,
				WriteLocal: false,
				Writes3:    true,
			},
		},
		WorkerConfig: worker.WorkerConfig{
			Ctx:          ctx,
			Id:           "config evaluation worker",
			Wg:           new(sync.WaitGroup),
			RequestChan:  configEvaluationWorkerRequestChan,
			ErrorChan:    errorChan,
			SdkClientMgr: awsClientMgr,
		},
	})
	// return errors
	if err != nil {
		return err
	}

	// create orphan policy scan worker
	var (
		eventTime                         = time.Now()
		orphanPolicyScanWorkerRequestChan = make(chan interface{}, 1)
	)

	orphanPolicyScanWorker, err := worker.NewOrphanPolicyWorker(worker.OrphanPolicyWorkerConfig{
		ConfigEvaluationChan: configEvaluationWorkerRequestChan,
		EventTime:            eventTime,
		WorkerConfig: worker.WorkerConfig{
			Ctx:          ctx,
			Id:           "orphan policy scan worker",
			Wg:           new(sync.WaitGroup),
			RequestChan:  orphanPolicyScanWorkerRequestChan,
			ErrorChan:    errorChan,
			SdkClientMgr: awsClientMgr,
		},
	})
	// return errors
	if err != nil {
		return err
	}

	log.Printf("length of aws accounts array : [%v]\n", len(config.AWSAccounts))
	executionErrorChan := make(chan error, len(config.AWSAccounts))
	executionErrorWg := new(sync.WaitGroup)
	executionErrorWg.Add(1)
	go func() {
		defer executionErrorWg.Done()
		for err := range executionErrorChan {
			log.Printf("error : [%v]\n", err)
			// send error to error worker
			errorChan <- err
		}
	}()

	for _, awsAccount := range config.AWSAccounts {
		result, ok := awsClientMgr.GetApi(awsAccount.AccountId, sdkapimgr.IamService)
		if !ok {
			log.Printf("error getting iam api client for account...skipping [%s]\n", awsAccount.AccountId)
			continue
		}
		iamApi := result.(iamapi.IamApi)
		orphanPolicyWorkerRequest := worker.OrphanPolicyWorkerRequest{
			AccountId: awsAccount.AccountId,
			IamApi:    iamApi,
		}
		orphanPolicyScanWorkerRequestChan <- orphanPolicyWorkerRequest // send request to orphan policy scan worker
		log.Printf("sent request to orphan policy scan worker for account [%s]\n", awsAccount.AccountId)
	}

	close(orphanPolicyScanWorkerRequestChan)
	log.Printf("orphan policy scan worker request channel closed")
	orphanPolicyScanWorker.Worker.Wait() // wait for all go routines to complete
	log.Printf("orphan policy scan worker go routines complete\n")

	close(configEvaluationWorkerRequestChan)
	log.Printf("config evaluation worker request channel closed")
	configEvaluationWorker.Worker.Wait() // wait for all go routines to complete
	log.Printf("config evaluation worker go routines complete\n")

	close(executionErrorChan)
	log.Printf("execution error channel closed")
	executionErrorWg.Wait() // wait for all go routines to complete
	log.Printf("execution error worker go routines complete\n")

	close(errorChan) // close error channel
	log.Printf("main thread error channel closed")
	close(errorCsvWorkerRequestChan) // close error csv worker request channel
	log.Printf("error csv worker request channel closed")

	errorWorkerWg.Wait() // wait for main thread error go routine
	log.Printf("main thread error go routine complete\n")
	errorCsvWorker.Worker.Wait() // wait for error csv worker
	log.Printf("error csv worker go routine complete\n")

	close(errorCsvWorkerErrorchan) // close error csv worker error channel
	log.Printf("error csv worker error channel closed")
	errorCsvWorkerErrorWg.Wait() // wait for error csv worker error go routine
	log.Printf("error csv worker error go routine complete\n")

	return nil
}
