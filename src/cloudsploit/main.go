package main

import (
	"context"

	mimosaxray "github.com/CyberAgent/mimosa-common/pkg/xray"
	"github.com/aws/aws-xray-sdk-go/xray"
	"github.com/kelseyhightower/envconfig"
)

type serviceConfig struct {
	EnvName string `default:"default" split_words:"true"`
}

func main() {
	var conf serviceConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	mimosaxray.InitXRay(xray.Config{})
	appLogger.Info("Start")
	ctx := context.Background()
	consumer := newSQSConsumer()
	appLogger.Info("Start the SQS consumer server for GCP CloudSploit...")
	consumer.Start(ctx,
		mimosaxray.MessageTracingHandler(conf.EnvName, "google.cloudsploit", newHandler()))
}
