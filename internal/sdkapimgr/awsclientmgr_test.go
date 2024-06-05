package sdkapimgr

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/accessanalyzerapi"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/configserviceapi"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/iamapi"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/s3api"
	"github.com/stretchr/testify/assert"
)

func TestSDKClientMgr(t *testing.T) {

	var (
		validAccountId     = "012345678910"
		invalidAccountId   = ""
		invalidServiceName = ""
		tests              = []struct {
			name                     string
			accountId                string
			serviceName              string
			expectedSetError         bool
			expectedGetError         bool
			expectedServiceNameError bool
		}{
			{
				"valid - s3 api", validAccountId, S3Service, false, false, false,
			},
			{
				"valid - iam api", validAccountId, IamService, false, false, false,
			},
			{
				"valid - access analyzer api", validAccountId, AccessAnalyzerService, false, false, false,
			},
			{
				"valid - configservice api", validAccountId, ConfigService, false, false, false,
			},
		}
	)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertion := assert.New(t)
			testClientMgr := NewAwsApiMgr()
			switch test.serviceName {
			case S3Service:
				{
					s3Client := &s3.Client{}
					err := testClientMgr.SetApi(test.accountId, S3Service, s3api.NewS3SDKClient(s3Client))
					assertion.NoError(err)
					result, ok := testClientMgr.GetApi(test.accountId, S3Service)
					assertion.NotNil(result)
					assertion.True(ok)
				}
			case IamService:
				{
					iamClient := &iam.Client{}
					err := testClientMgr.SetApi(test.accountId, IamService, iamapi.NewIamApi(iamClient))
					assertion.NoError(err)
					result, ok := testClientMgr.GetApi(test.accountId, IamService)
					assertion.NotNil(result)
					assertion.True(ok)
				}
			case AccessAnalyzerService:
				{
					accessAnalyzerClient := &accessanalyzer.Client{}
					err := testClientMgr.SetApi(test.accountId, AccessAnalyzerService, accessanalyzerapi.NewAccessAnalyzerApi((accessAnalyzerClient)))
					assertion.NoError(err)
					result, ok := testClientMgr.GetApi(test.accountId, AccessAnalyzerService)
					assertion.NotNil(result)
					assertion.True(ok)

				}
			case ConfigService:
				{
					configServiceClient := &configservice.Client{}
					err := testClientMgr.SetApi(test.accountId, ConfigService, configserviceapi.NewConfigServiceApi(configServiceClient))
					assertion.NoError(err)
					result, ok := testClientMgr.GetApi(test.accountId, ConfigService)
					assertion.NotNil(result)
					assertion.True(ok)

				}
			default:
				{
					assertion.True(test.expectedServiceNameError)
				}
			}
		})
	}
	var (
		setErrorTests = []struct {
			name        string
			accountId   string
			serviceName string
			client      interface{}
		}{
			{
				"invalid - empty account id", invalidAccountId, S3Service, nil,
			},
			{
				"invalid - empty servicename", validAccountId, invalidServiceName, nil,
			},
			{
				"invalid - empty client", validAccountId, S3Service, nil,
			},
			{
				"invalid - invalid service name", validAccountId, "invalidServiceName", iamapi.NewIamApi(&iam.Client{}),
			},
			{
				"s3 api type assertion error", validAccountId, S3Service, iamapi.NewIamApi(&iam.Client{}),
			},
			{
				"iam api type assertion error", validAccountId, IamService, s3api.NewS3SDKClient(&s3.Client{}),
			},
			{
				"access analyzer api type assertion error", validAccountId, AccessAnalyzerService, configserviceapi.NewConfigServiceApi(&configservice.Client{}),
			},
			{
				"config service api type assertion error", validAccountId, ConfigService, accessanalyzerapi.NewAccessAnalyzerApi(&accessanalyzer.Client{}),
			},
		}
		getErrorTests = []struct {
			name        string
			accountId   string
			serviceName string
		}{
			{
				"invalid - empty account id", invalidAccountId, S3Service,
			},
			{
				"invalid - empty servicename", validAccountId, invalidServiceName,
			},
		}
	)

	for _, test := range setErrorTests {
		t.Run(test.name, func(t *testing.T) {
			assertion := assert.New(t)
			testClientMgr := NewAwsApiMgr()
			err := testClientMgr.SetApi(test.accountId, test.serviceName, test.client)
			assertion.Error(err)
		})
	}

	for _, test := range getErrorTests {
		t.Run(test.name, func(t *testing.T) {
			assertion := assert.New(t)
			testClientMgr := NewAwsApiMgr()
			result, ok := testClientMgr.GetApi(test.accountId, test.serviceName)
			assertion.False(ok)
			assertion.Nil(result)
		})
	}
}
