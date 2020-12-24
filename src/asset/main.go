package main

import (
	"context"
)

func main() {
	appLogger.Info("Start")
	ctx := context.Background()
	consumer := newSQSConsumer()
	appLogger.Info("Start the GCP Cloud Asset Inventory SQS consumer server...")
	consumer.Start(ctx, newHandler())
}
