package main

import (
	"context"
	"errors"
	"log"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/handlers"
)

func handler(ctx context.Context, event events.ConfigEvent) error {
	log.Printf("incoming event : [%+v]\n", event)

	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion("us-east-1"),
		config.WithRetryMode(aws.RetryModeStandard),
		config.WithRetryMaxAttempts(3))
	// return errors
	if err != nil {
		return errors.New("failed to load aws config : " + err.Error())
	}

	checkAccessNotGrantedHandler, err := handlers.NewCheckAccessNotGrantedHandler(cfg)
	if err != nil {
		log.Printf("error : [%v]\n", err.Error())
		return err
	}

	err = checkAccessNotGrantedHandler.Handle(ctx, handlers.CheckAccessNotGrantedEvent{
		ConfigEvent: event,
	})
	if err != nil {
		log.Printf("error : [%v]\n", err.Error())
	}

	return nil
}

func main() {
	lambda.Start(handler)
}
