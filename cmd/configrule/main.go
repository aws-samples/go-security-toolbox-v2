package main

import (
	"context"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	appconfig "github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/config"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/errors"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/handlers"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/logger"
)

const (
	defaultRegion       = "us-east-1"
	defaultRetryAttempts = 3
)

func loadAWSConfig() (aws.Config, error) {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = defaultRegion
	}
	return config.LoadDefaultConfig(context.Background(),
		config.WithRegion(region),
		config.WithRetryMode(aws.RetryModeStandard),
		config.WithRetryMaxAttempts(defaultRetryAttempts))
}

func handler(ctx context.Context, event events.ConfigEvent) error {
	log := logger.NewLogger()
	log.Info("incoming event: [%+v]", event)

	cfg, err := loadAWSConfig()
	if err != nil {
		return errors.New("failed to load aws config", err)
	}

	configMgr, err := appconfig.NewConfigManager()
	if err != nil {
		log.Error("failed to create config manager: %v", err)
		return err
	}

	router, err := handlers.NewRuleRouter(cfg, log, configMgr)
	if err != nil {
		log.Error("failed to create rule router: %v", err)
		return err
	}

	return router.Route(ctx, event)
}

func main() {
	lambda.Start(handler)
}