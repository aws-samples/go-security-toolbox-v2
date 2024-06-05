package worker

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	configservicetypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/configserviceapi"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/sdkapimgr"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/shared"
)

type ConfigEvaluationWorker struct {
	maxBatchSize            int
	accountId               string // account id to send config evaluations to
	configEvaluations       []configservicetypes.Evaluation
	resultToken             string              // result token for sending aws config evaluations
	testMode                bool                // config service boolean for testing
	csvWorkerRequestChannel chan interface{}    // channel to send request to csv worker
	csvWorkerWg             *sync.WaitGroup     // wait group for csv worker
	csvWorkerEnabled        bool                // boolean to enable csv worker for writing results to local filesystem of s3
	outputConfiguration     OutputConfiguration // output configuration for csv worker
	Worker                  Worker              // worker interface
}

type ConfigEvaluationWorkerConfig struct {
	AccountId        string
	ResultToken      string
	TestMode         bool
	CsvWorkerEnabled bool
	CsvWorkerConfig  CsvWorkerConfig
	WorkerConfig     WorkerConfig
}

type ConfigEvaluationWorkerRequest struct {
	ConfigEvaluation configservicetypes.Evaluation
}

func NewConfigEvaluationWorker(config ConfigEvaluationWorkerConfig) (*ConfigEvaluationWorker, error) {

	// initalize worker interface
	worker, err := NewWorker(config.WorkerConfig)
	if err != nil {
		return nil, errors.New("invalid worker config: " + err.Error())
	}

	// if csv worker is enabled, create a new csv worker
	if config.CsvWorkerEnabled {
		_, err := NewCSVWorker(config.CsvWorkerConfig)
		if err != nil {
			return nil, errors.New("invalid csv worker config: " + err.Error())
		}
	}

	// validate aws account id
	if !shared.IsValidAwsAccountId(config.AccountId) {
		log.Printf("invalid aws account id: %s", config.AccountId)
		return nil, errors.New("invalid aws account id")
	}

	// check that result token is not empty if test mode is false
	if !config.TestMode && config.ResultToken == "" {
		log.Printf("test mode is set to [%v] and result token is not set\n", config.TestMode)
		return nil, errors.New("invalid result token")
	}

	// create csv worker
	configEvaluationWorker := &ConfigEvaluationWorker{
		maxBatchSize:            100,
		accountId:               config.AccountId,
		configEvaluations:       []configservicetypes.Evaluation{},
		resultToken:             config.ResultToken,
		testMode:                config.TestMode,
		csvWorkerEnabled:        config.CsvWorkerEnabled,
		csvWorkerRequestChannel: config.CsvWorkerConfig.WorkerConfig.RequestChan,
		csvWorkerWg:             config.CsvWorkerConfig.WorkerConfig.Wg,
		outputConfiguration:     config.CsvWorkerConfig.OutputConfig,
		Worker:                  worker,
	}

	worker.SetRequestHandler(configEvaluationWorker) // set request handler
	worker.SetFinalizer(configEvaluationWorker)      // set finalizer

	return configEvaluationWorker, nil

}

func (cew *ConfigEvaluationWorker) Handle(params interface{}) {
	errorChan := cew.Worker.GetErrorChannel()           // get error channel
	csvWorkerRequestChan := cew.csvWorkerRequestChannel // get csv worker request channel
	resultToken := cew.resultToken                      // get result token
	awsClientMgr := cew.Worker.GetSDKClientMgr()        // get aws client manager

	client, _ := awsClientMgr.GetApi(cew.accountId, sdkapimgr.ConfigService) // retrieve aws config client from client map
	configClient := client.(configserviceapi.ConfigServiceApi)               // type assert to aws config client type

	request := params.(ConfigEvaluationWorkerRequest) // type assert request to config evaluation worker request
	configEvaluation := request.ConfigEvaluation      // get config evaluation from request

	cew.configEvaluations = append(cew.configEvaluations, configEvaluation) // append config evaluation to config evaluation batch

	// if csv worker is enabled, send request to csv worker channel
	if cew.csvWorkerEnabled {
		csvRecord := []string{
			*configEvaluation.ComplianceResourceId,
			*configEvaluation.ComplianceResourceType,
			string(configEvaluation.ComplianceType),
			*configEvaluation.Annotation,
			configEvaluation.OrderingTimestamp.Format(time.RFC3339),
		}
		csvWorkerRequestChan <- CsvWorkerRequest{
			CsvRecord: csvRecord,
		}
	}

	// if the length is max batch size, send to aws config service
	if len(cew.configEvaluations) == cew.maxBatchSize {
		_, err := configClient.PutEvaluations(context.Background(), &configservice.PutEvaluationsInput{
			Evaluations: cew.configEvaluations,
			ResultToken: aws.String(resultToken),
			TestMode:    cew.testMode,
		})
		if err != nil {
			log.Printf("error sending config evaluations to aws config service: %v\n", err)
			errorChan <- err // send error to error channel
		}
		log.Printf("worker [%v] successfully sent [%v] aws config evaluations\n", cew.Worker.GetId(), cew.maxBatchSize)
		cew.configEvaluations = []configservicetypes.Evaluation{} // clear config evaluation batch
	}

}

func (cew *ConfigEvaluationWorker) Finalize() {
	log.Printf("finalizing worker [%v]\n", cew.Worker.GetId())
	log.Printf("length of config evaluations : %v\n", len(cew.configEvaluations))
	errorChan := cew.Worker.GetErrorChannel()                                // get error channel
	awsClientMgr := cew.Worker.GetSDKClientMgr()                             // get aws client manager
	client, _ := awsClientMgr.GetApi(cew.accountId, sdkapimgr.ConfigService) // retrieve aws config client from client map
	configClient := client.(configserviceapi.ConfigServiceApi)               // type assert to aws config client type
	csvWorkerWg := cew.csvWorkerWg                                           // get csv worker wait group
	csvWorkerRequestchannel := cew.csvWorkerRequestChannel

	// close csv worker request channel if exists
	if csvWorkerRequestchannel != nil {
		close(csvWorkerRequestchannel)
	}

	// send any remaining config evaluations to aws config service
	if len(cew.configEvaluations) > 0 {
		_, err := configClient.PutEvaluations(context.Background(), &configservice.PutEvaluationsInput{
			Evaluations: cew.configEvaluations,
			ResultToken: aws.String(cew.resultToken),
			TestMode:    cew.testMode,
		})
		if err != nil {
			errorChan <- err // send error to error channel
		}
		log.Printf("worker [%v] successfully sent [%v] aws config evaluations\n", cew.Worker.GetId(), len(cew.configEvaluations))
		cew.configEvaluations = []configservicetypes.Evaluation{} // clear config evaluation batch
	}

	// wait for csv worker to finish if exists
	if csvWorkerWg != nil {
		csvWorkerWg.Wait()
	}

	log.Printf("worker [%v] successfully finalized\n", cew.Worker.GetId())
}
