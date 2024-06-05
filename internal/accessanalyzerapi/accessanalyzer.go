package accessanalyzerapi

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
)

type AccessAnalyzerApi interface {
	// check access not granted
	CheckAccessNotGranted(ctx context.Context, params *accessanalyzer.CheckAccessNotGrantedInput, optFns ...func(*accessanalyzer.Options)) (*accessanalyzer.CheckAccessNotGrantedOutput, error)
}

type _AccessAnalyzerApi struct {
	client *accessanalyzer.Client // access analyzer client
}

func NewAccessAnalyzerApi(client *accessanalyzer.Client) AccessAnalyzerApi {
	return &_AccessAnalyzerApi{
		client: client,
	}
}

// check access not granted
func (a *_AccessAnalyzerApi) CheckAccessNotGranted(ctx context.Context, params *accessanalyzer.CheckAccessNotGrantedInput, optFns ...func(*accessanalyzer.Options)) (*accessanalyzer.CheckAccessNotGrantedOutput, error) {
	return a.client.CheckAccessNotGranted(ctx, params, optFns...)
}
