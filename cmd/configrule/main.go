package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
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
	logger.Info.Printf("Processing event: %+v", event)

	cfg, err := loadAWSConfig()
	if err != nil {
		return fmt.Errorf("failed to load aws config: %w", err)
	}

	return handlers.RouteConfigRule(ctx, event, cfg)
}

func main() {
	lambda.Start(handler)
}