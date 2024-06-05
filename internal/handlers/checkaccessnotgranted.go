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
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/accessanalyzerapi"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/iamapi"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/s3api"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/sdkapimgr"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/shared"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/worker"
)

type Handler interface {
	Handle(ctx context.Context, params interface{}) error
}

type _CheckAccessNotGrantedHandler struct {
	s3Api s3api.S3Api
}

type CheckAccessNotGrantedEvent struct {
	ConfigEvent events.ConfigEvent
}

type CheckAccessNotGrantedConfig struct {
	AWSAccounts               []shared.AWSAccount `json:"awsAccounts"`
	PrecompliantIamIdentities []string            `json:"precompliantIamIdentities"`
	RestrictedActions         []string            `json:"restrictedActions"`
	TestMode                  bool                `json:"testMode"`
	Prefix                    string              `json:"prefix"`
}

func NewCheckAccessNotGrantedHandler(cfg aws.Config) (Handler, error) {
	cangHandler := &_CheckAccessNotGrantedHandler{
		s3Api: s3api.NewS3SDKClient(s3.NewFromConfig(cfg)),
	}

	return cangHandler, nil
}

func (cang *_CheckAccessNotGrantedHandler) Handle(ctx context.Context, params interface{}) error {
	event, ok := params.(CheckAccessNotGrantedEvent)
	if !ok {
		return errors.New("type assertion failure.  event is not type checkaccessnotgranted event")
	}

	// read environment variables for config file location
	configBucketName := os.Getenv(shared.EnvBucketName)
	log.Printf("config bucket name : [%s]\n", configBucketName)
	configFileObjectKey := os.Getenv(shared.EnvConfigFileKey)
	log.Printf("config file object key : [%s]\n", configFileObjectKey)

	if configBucketName == "" || configFileObjectKey == "" {
		return errors.New("env vars not set")
	}

	// retrieve config file from s3
	getObjectOutput, err := cang.s3Api.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(configBucketName),
		Key:    aws.String(configFileObjectKey),
	})
	// return errors
	if err != nil {
		return err
	}

	var config CheckAccessNotGrantedConfig
	objectContent, err := io.ReadAll(getObjectOutput.Body)
	// return errors
	if err != nil {
		return err
	}
	log.Printf("config file content : [%s]\n", string(objectContent))

	err = json.Unmarshal(objectContent, &config)
	// return errors
	if err != nil {
		return err
	}
	log.Printf("config file unmarshalled : [%+v]\n", config)

	// check if restricted actions are valid
	if len(config.RestrictedActions) == 0 {
		return errors.New("restricted actions are empty")
	}

	for _, restrictedAction := range config.RestrictedActions {
		if !shared.IsValidAction(restrictedAction) {
			return errors.New("restricted action(s) are invalid: " + restrictedAction)
		}
	}
	log.Printf("restricted actions : [%+v]\n", config.RestrictedActions)

	// check if precompliant iam identities are valid
	for _, precompliantIamIdentity := range config.PrecompliantIamIdentities {
		if precompliantIamIdentity == "" {
			log.Println("precompliant iam identity is empty...skipping")
			continue
		}
		if !shared.IsValidIamIdentityArn(precompliantIamIdentity) {
			return errors.New("precompliant iam identity(s) are invalid: " + precompliantIamIdentity)
		}
	}

	// create a map of precompliant policy arns
	preCompliantIamIdentites := make(map[string]bool)
	for _, precompliantIamIdentity := range config.PrecompliantIamIdentities {
		preCompliantIamIdentites[precompliantIamIdentity] = true
	}

	// ensure all keys for map equal true
	for key, value := range preCompliantIamIdentites {
		if !value {
			return errors.New("precompliant iam identities map was not initialized correctly: [" + key + " ]")
		}
	}
	log.Println("precompliant iam identities validated")

	// check if test mode is enabled

	var (
		batchErrors               = make([]error, 0)
		errorChan                 = make(chan error, 1)
		errorCsvWorkerRequestChan = make(chan interface{}, 1)
		errorCsvWorkerErrorChan   = make(chan error, 1)
	)

	// load aws config
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion("us-east-1"),
		awsconfig.WithRetryMode(aws.RetryModeStandard),
		awsconfig.WithRetryMaxAttempts(3))

	// return errors
	if err != nil {
		return err
	}

	// initalize aws client manager
	awsClientMgr, err := sdkapimgr.InitAwsClientMgr(sdkapimgr.SDKApiMgrConfig{
		Cfg:           cfg,
		MainAccountId: event.ConfigEvent.AccountID,
		AwsAccounts:   config.AWSAccounts,
	})
	// return error
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
			ErrorChan:    errorCsvWorkerErrorChan,
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

	// process errors from error channel
	errorCsvWorkerErrorWg := new(sync.WaitGroup)
	errorCsvWorkerErrorWg.Add(1)
	go func() {
		defer errorCsvWorkerErrorWg.Done()
		for err := range errorChan {
			batchErrors = append(batchErrors, err)
		}
		if len(batchErrors) > 0 {
			log.Printf("errors from error worker : [%+v]\n", batchErrors)
			return
		}
	}()

	errorWorkerWg := new(sync.WaitGroup)
	errorWorkerWg.Add(1)
	go func() {
		defer errorWorkerWg.Done()
		for err := range errorChan {
			log.Printf("error from main threads error channel: [%s]\n", err.Error())
			errorCsvWorkerRequestChan <- worker.CsvWorkerRequest{
				CsvRecord: []string{err.Error()},
			}
		}
	}()

	// create config evaluation worker
	var (
		configEvaluationWorkerRequestChan    = make(chan interface{}, 1)
		configEvaluationCsvWorkerRequestChan = make(chan interface{}, 1)
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
				RequestChan:  configEvaluationCsvWorkerRequestChan,
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

	// create custom policy scan worker
	var (
		customPolicyScanWorkerRequestChan = make(chan interface{}, 1)
		semaphoreChan                     = make(chan chan interface{}, 3)
		eventTime                         = time.Now()
	)

	customPolicyScanWorker, err := worker.NewCustomPolicyScanWorker(worker.CustomPolicyScanWorkerConfig{
		RestrictedActions:    config.RestrictedActions,
		ConfigEvaluationChan: configEvaluationWorkerRequestChan,
		SemaphoreChan:        semaphoreChan,
		EventTime:            eventTime,
		EnableCache:          true,
		WorkerConfig: worker.WorkerConfig{
			Ctx:          ctx,
			Id:           "custom policy scan worker",
			Wg:           new(sync.WaitGroup),
			RequestChan:  customPolicyScanWorkerRequestChan,
			ErrorChan:    errorChan,
			SdkClientMgr: awsClientMgr,
		},
	})
	// return errors
	if err != nil {
		return err
	}

	executionWg := new(sync.WaitGroup)
	for _, awsAccount := range config.AWSAccounts {
		executionWg.Add(1)
		go cang.checkAccessNotGrantedByAccount(CheckAccessNotGrantedByAccountInput{
			wg:                        executionWg,
			accountId:                 awsAccount.AccountId,
			awsClientMgr:              awsClientMgr,
			errorChan:                 errorChan,
			workerRequestChan:         customPolicyScanWorkerRequestChan,
			precompliantIamIdentities: preCompliantIamIdentites,
		})
	}

	executionWg.Wait() // wait for go routines to complete
	log.Printf("checkaccessnotgrantedbyaccount go routines successfully sent all requests\n")
	close(customPolicyScanWorkerRequestChan) // close request channel
	log.Printf("custom policy scan worker request channel closed\n")
	customPolicyScanWorker.Worker.Wait() // wait for custom policy scan workers to complete
	log.Printf("custom policy scan worker completed\n")

	// wait for config evaluation worker
	close(configEvaluationWorkerRequestChan)
	log.Printf("config evaluation worker request channel closed\n")
	configEvaluationWorker.Worker.Wait()
	log.Printf("config evalation worker completed\n")

	// wait for error worker
	close(errorChan)
	log.Printf("main thread error channel closed\n")
	close(errorCsvWorkerRequestChan)
	log.Printf("error csv worker request channel closed\n")

	errorWorkerWg.Wait()
	log.Printf("main thread error go routine completed\n")
	errorCsvWorker.Worker.Wait()
	log.Printf("error csv worker go routine completed\n")

	close(errorCsvWorkerErrorChan)
	log.Printf("error csv worker error channel closed\n")
	errorCsvWorkerErrorWg.Wait()
	log.Printf("error csv worker error go routine completed\n")

	return nil
}

type CheckAccessNotGrantedByAccountInput struct {
	wg                        *sync.WaitGroup
	accountId                 string
	awsClientMgr              sdkapimgr.SdkApiMgr
	errorChan                 chan error
	workerRequestChan         chan interface{}
	precompliantIamIdentities map[string]bool
}

func (cang *_CheckAccessNotGrantedHandler) checkAccessNotGrantedByAccount(input CheckAccessNotGrantedByAccountInput) {
	log.Printf("checkaccessnotgranted start for account [%s]\n", input.accountId)
	defer input.wg.Done()
	// retrieve sdk clients from sdk client manager interface
	result, ok := input.awsClientMgr.GetApi(input.accountId, sdkapimgr.IamService)
	if !ok {
		log.Printf("error retrieving iam client from sdk client manager interface")
		input.errorChan <- errors.New("error retrieving iam client from sdk client manager interface")
	}
	iamApi, ok := result.(iamapi.IamApi)
	if !ok {
		log.Printf("error type assertion for iam client")
		input.errorChan <- errors.New("error type assertion for iam client")
	}

	result, ok = input.awsClientMgr.GetApi(input.accountId, sdkapimgr.AccessAnalyzerService)
	if !ok {
		log.Printf("error retrieving access analyzer client from sdk client manager interface")
		input.errorChan <- errors.New("error retrieving access analyzer client from sdk client manager interface")
	}
	accessAnalyzerApi, ok := result.(accessanalyzerapi.AccessAnalyzerApi)
	if !ok {
		log.Printf("error type assertion for access analyzer client")
		input.errorChan <- errors.New("error type assertion for access analyzer client")
	}

	roleWg := new(sync.WaitGroup)
	roleWg.Add(1)
	go func() {
		defer roleWg.Done()
		err := iamRoleCheckAccessNotGranted(iamRoleCheckAccessNotGrantedInput{
			accountId:                 input.accountId,
			iamClient:                 iamApi,
			accessAnalyzer:            accessAnalyzerApi,
			workerRequestChan:         input.workerRequestChan,
			precompliantIamIdentities: input.precompliantIamIdentities,
		})
		if err != nil {
			log.Printf("error checking role access : %v", err)
			input.errorChan <- errors.New("error checking role access : [%v]")
		}
	}()

	userWg := new(sync.WaitGroup)
	userWg.Add(1)
	go func() {
		defer userWg.Done()
		err := iamUserCheckAccessNotGranted(iamUserCheckAccessNotGrantedInput{
			accountId:                 input.accountId,
			iamClient:                 iamApi,
			accessAnalyzer:            accessAnalyzerApi,
			workerRequestChan:         input.workerRequestChan,
			precompliantIamIdentities: input.precompliantIamIdentities,
		})
		if err != nil {
			log.Printf("error checking user access : %v", err)
			input.errorChan <- errors.New("error checking user access : [%v]")
		}
	}()

	// wait for go routines to complete
	roleWg.Wait()
	userWg.Wait()
	log.Printf("finished checking access for account [%s]\n", input.accountId)
}

type iamRoleCheckAccessNotGrantedInput struct {
	accountId                 string
	iamClient                 iamapi.IamApi
	accessAnalyzer            accessanalyzerapi.AccessAnalyzerApi
	workerRequestChan         chan interface{}
	precompliantIamIdentities map[string]bool
}

func iamRoleCheckAccessNotGranted(input iamRoleCheckAccessNotGrantedInput) error {
	log.Printf("processing roles for account [%s]\n", input.accountId)
	if input.workerRequestChan == nil {
		log.Printf("worker request channel is nil...exiting\n")
		return errors.New("worker request channel is nil")
	}
	listRolesPaginator := iam.NewListRolesPaginator(input.iamClient, &iam.ListRolesInput{})
	for listRolesPaginator.HasMorePages() {
		listRolesOutput, err := listRolesPaginator.NextPage(context.TODO())
		if err != nil {
			log.Printf("error listing roles : %v", err)
			return errors.New("error listing roles : [%v]")
		}
		for _, role := range listRolesOutput.Roles {
			// send request to worker
			iamIdentity, err := worker.NewIamIdentity(worker.IamIdentityConfig{
				IdentityType: shared.AwsIamRole,
				Arn:          *role.Arn,
				Name:         *role.RoleName,
			})
			// return errors
			if err != nil {
				return err
			}

			request := worker.CustomPolicyScanWorkerRequest{
				AccountId:                      input.accountId,
				ResourceType:                   shared.AwsIamRole,
				IamIdentity:                    iamIdentity,
				IamApi:                         input.iamClient,
				AccessAnalyzerApi:              input.accessAnalyzer,
				PrecompliantIamIdentityRequest: false,
			}

			// if role is precompliant, send precompliant request
			if input.precompliantIamIdentities[*role.Arn] {
				request.PrecompliantIamIdentityRequest = true
			}

			input.workerRequestChan <- request // send request to worker
		}
	}
	return nil
}

type iamUserCheckAccessNotGrantedInput struct {
	accountId                 string
	iamClient                 iamapi.IamApi
	accessAnalyzer            accessanalyzerapi.AccessAnalyzerApi
	workerRequestChan         chan interface{}
	precompliantIamIdentities map[string]bool
}

func iamUserCheckAccessNotGranted(input iamUserCheckAccessNotGrantedInput) error {
	log.Printf("processing users for account [%s]\n", input.accountId)
	if input.workerRequestChan == nil {
		log.Println("worker request channel is nil...exiting")
		return errors.New("worker request channel is nil")
	}
	listUsersPaginator := iam.NewListUsersPaginator(input.iamClient, &iam.ListUsersInput{})
	for listUsersPaginator.HasMorePages() {
		listUsersOutput, err := listUsersPaginator.NextPage(context.TODO())
		if err != nil {
			log.Printf("error listing users : %v", err)
			return errors.New("error listing users : [%v]")
		}
		for _, user := range listUsersOutput.Users {
			// send request to worker
			iamIdentity, err := worker.NewIamIdentity(worker.IamIdentityConfig{
				IdentityType: shared.AwsIamUser,
				Arn:          *user.Arn,
				Name:         *user.UserName,
			})
			// return errors
			if err != nil {
				return err
			}

			request := worker.CustomPolicyScanWorkerRequest{
				AccountId:                      input.accountId,
				ResourceType:                   shared.AwsIamUser,
				IamIdentity:                    iamIdentity,
				IamApi:                         input.iamClient,
				AccessAnalyzerApi:              input.accessAnalyzer,
				PrecompliantIamIdentityRequest: false,
			}

			// if user is precompliant, send precompliant request
			if input.precompliantIamIdentities[*user.Arn] {
				request.PrecompliantIamIdentityRequest = true
			}

			input.workerRequestChan <- request // send request to worker
		}
	}
	return nil
}
