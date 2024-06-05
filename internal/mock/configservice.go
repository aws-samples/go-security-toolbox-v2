package mock

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/configservice"
)

type MockConfigService struct {
}

func (m *MockConfigService) PutEvaluations(ctx context.Context, params *configservice.PutEvaluationsInput, optFns ...func(*configservice.Options)) (*configservice.PutEvaluationsOutput, error) {
	return &configservice.PutEvaluationsOutput{}, nil
}
