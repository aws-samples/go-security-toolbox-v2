package sdkapimgr

import (
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/accessanalyzerapi"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/configserviceapi"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/iamapi"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/keyvaluestore"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/s3api"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/shared"
)

type SdkApiMgr interface {
	GetApi(accountId string, serviceName string) (interface{}, bool)
	SetApi(accountId string, serviceName string, client interface{}) error
}

type awsApiMgr struct {
	apiMap keyvaluestore.KeyValueStore
}

type SDKApiMgrConfig struct {
	Cfg           aws.Config
	MainAccountId string
	AwsAccounts   []shared.AWSAccount
}

const (
	S3Service             string = "s3"              // simple storage service (s3)
	ConfigService         string = "config-service"  // AWS Config service
	IamService            string = "iam"             // identity and access management (iam)
	AccessAnalyzerService string = "access-analyzer" // AWS Access Analyzer
)

// initialize instance of aws client mgr
func InitAwsClientMgr(config SDKApiMgrConfig) (SdkApiMgr, error) {

	// check if main account id is empty
	if config.MainAccountId == "" {
		return nil, errors.New("main account id is required")
	}

	// check if credentials are nil
	if config.Cfg.Credentials == nil {
		return nil, errors.New("valid config credentials provider required")
	}

	// check if aws accounts are empty
	if len(config.AwsAccounts) == 0 {
		return nil, errors.New("aws accounts cannot be empty") // return aws client mgr and error if aws accounts are empty
	}

	awscm := NewAwsApiMgr()

	cfgCopy := config.Cfg.Copy() // create copy of aws config

	configServiceClient := configservice.NewFromConfig(cfgCopy)                   // create config service client for main account
	configServiceApi := configserviceapi.NewConfigServiceApi(configServiceClient) // create config service api for main account
	awscm.SetApi(config.MainAccountId, ConfigService, configServiceApi)           // add config service client for main account

	accessAnalyzerClient := accessanalyzer.NewFromConfig(cfgCopy)                     // create access analyzer for main account
	accessAnalyzerApi := accessanalyzerapi.NewAccessAnalyzerApi(accessAnalyzerClient) // create access analyzer api for main account
	awscm.SetApi(config.MainAccountId, AccessAnalyzerService, accessAnalyzerApi)      // add access analyzer client for main account

	s3Client := s3.NewFromConfig(cfgCopy)                // create s3 client for main account
	s3Api := s3api.NewS3SDKClient(s3Client)              // create s3 api for main account
	awscm.SetApi(config.MainAccountId, S3Service, s3Api) // add s3 clien for main account

	iamClient := iam.NewFromConfig(cfgCopy)                // create iam client for main account
	iamApi := iamapi.NewIamApi(iamClient)                  // create iam api for main account
	awscm.SetApi(config.MainAccountId, IamService, iamApi) // add iam client for main account

	// loop through aws accounts and create & add iam & access analyzer clients to aws client mgr
	stsClient := sts.NewFromConfig(cfgCopy) // create sts client for assume role operations
	for _, awsAccount := range config.AwsAccounts {
		creds := stscreds.NewAssumeRoleProvider(stsClient, awsAccount.RoleArn) // assume role from iam role arn
		cfgCopy.Credentials = creds

		iamClient := iam.NewFromConfig(cfgCopy)                // create iam client for aws account
		iamApi := iamapi.NewIamApi(iamClient)                  // create iam api for aws account
		awscm.SetApi(awsAccount.AccountId, IamService, iamApi) // add iam client for aws account

		accessAnalyzerClient := accessanalyzer.NewFromConfig(cfgCopy)                     // create access analyzer client for aws account
		accessAnalyzerApi := accessanalyzerapi.NewAccessAnalyzerApi(accessAnalyzerClient) // create access analyzer api for aws account
		awscm.SetApi(awsAccount.AccountId, AccessAnalyzerService, accessAnalyzerApi)      // add access analyzer client for aws account
	}

	return awscm, nil
}

func NewAwsApiMgr() SdkApiMgr {
	return &awsApiMgr{
		apiMap: keyvaluestore.NewKeyValueStore(),
	}
}

// get sdk client
func (awscm *awsApiMgr) GetApi(accountId string, serviceName string) (interface{}, bool) {
	if accountId == "" || serviceName == "" {
		return nil, false
	}
	key := shared.Key{
		PrimaryKey: accountId,
		SortKey:    serviceName,
	}
	return awscm.apiMap.Get(key)
}

// set sdk client
func (awscm *awsApiMgr) SetApi(accountId string, serviceName string, client interface{}) error {
	if accountId == "" || serviceName == "" || client == nil {
		return errors.New("required field(s) cannot be empty")
	}

	key := shared.Key{
		PrimaryKey: accountId,
		SortKey:    serviceName,
	}
	switch serviceName {
	case S3Service:
		if _, ok := client.(s3api.S3Api); !ok {
			return errors.New("invalid s3 client")
		}
	case ConfigService:
		if _, ok := client.(configserviceapi.ConfigServiceApi); !ok {
			return errors.New("invalid config service client")
		}
	case IamService:
		if _, ok := client.(iamapi.IamApi); !ok {
			return errors.New("invalid iam client")
		}
	case AccessAnalyzerService:
		if _, ok := client.(accessanalyzerapi.AccessAnalyzerApi); !ok {
			return errors.New("invalid access analyzer client")
		}
	default:
		return errors.New("invalid service name")
	}

	awscm.apiMap.Set(key, client)
	return nil
}
