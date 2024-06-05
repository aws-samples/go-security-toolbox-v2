package configserviceapi

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/configservice"
)

type ConfigServiceApi interface {
	// put evaluations
	PutEvaluations(ctx context.Context, params *configservice.PutEvaluationsInput, optFns ...func(*configservice.Options)) (*configservice.PutEvaluationsOutput, error)
}

type _ConfigServiceApi struct {
	client *configservice.Client
}

func NewConfigServiceApi(client *configservice.Client) ConfigServiceApi {
	return &_ConfigServiceApi{
		client: client,
	}
}

func (configApi *_ConfigServiceApi) PutEvaluations(ctx context.Context, params *configservice.PutEvaluationsInput, optFns ...func(*configservice.Options)) (*configservice.PutEvaluationsOutput, error) {
	return configApi.client.PutEvaluations(ctx, params, optFns...)
}
