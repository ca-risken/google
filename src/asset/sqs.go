package main

import (
	"context"

	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/go-sqs-poller/worker/v5"
)

type SQSConfig struct {
	Debug string

	AWSRegion   string
	SQSEndpoint string

	AssetQueueName     string
	AssetQueueURL      string
	MaxNumberOfMessage int32
	WaitTimeSecond     int32
}

func newSQSConsumer(ctx context.Context, conf *SQSConfig) *worker.Worker {
	if conf.Debug == "true" {
		appLogger.Level(logging.DebugLevel)
	}

	client, err := worker.CreateSqsClient(ctx, conf.AWSRegion, conf.SQSEndpoint)
	if err != nil {
		appLogger.Fatalf(ctx, "failed to create a new client, %v", err)
	}

	appLogger.Infof(ctx, "created SQS client, sqsConfig=%+v", conf)
	return &worker.Worker{
		Config: &worker.Config{
			QueueName:          conf.AssetQueueName,
			QueueURL:           conf.AssetQueueURL,
			MaxNumberOfMessage: conf.MaxNumberOfMessage,
			WaitTimeSecond:     conf.WaitTimeSecond,
		},
		Log:       appLogger,
		SqsClient: client,
	}
}
