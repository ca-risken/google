package main

import (
	"context"
)

func main() {
	appLogger.Info("Start")
	ctx := context.Background()
	consumer := newSQSConsumer()
	appLogger.Info("Start the SQS consumer server for GCP Security Command Center...")
	consumer.Start(ctx, newHandler())
}
