package main

import (
	"context"

	"github.com/aws/aws-xray-sdk-go/xray"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	mimosaxray "github.com/ca-risken/common/pkg/xray"
	"github.com/gassara-kys/envconfig"
)

type AppConfig struct {
	EnvName string `default:"local" split_words:"true"`

	// sqs
	Debug string `default:"false"`

	AWSRegion   string `envconfig:"aws_region"   default:"ap-northeast-1"`
	SQSEndpoint string `envconfig:"sqs_endpoint" default:"http://queue.middleware.svc.cluster.local:9324"`

	PortscanQueueName  string `split_words:"true" default:"google-portscan"`
	PortscanQueueURL   string `split_words:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/google-portscan"`
	MaxNumberOfMessage int64  `split_words:"true" default:"10"`
	WaitTimeSecond     int64  `split_words:"true" default:"20"`

	// grpc
	FindingSvcAddr string `required:"true" split_words:"true" default:"finding.core.svc.cluster.local:8001"`
	AlertSvcAddr   string `required:"true" split_words:"true" default:"alert.core.svc.cluster.local:8004"`
	GoogleSvcAddr  string `required:"true" split_words:"true" default:"google.google.svc.cluster.local:11001"`

	// portscan
	GoogleCredentialPath  string `required:"true" split_words:"true" default:"/tmp/credential.json"`
	ScanExcludePortNumber int    `split_words:"true"                 default:"1000"`
}

func main() {
	var conf AppConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	err = mimosaxray.InitXRay(xray.Config{})
	if err != nil {
		appLogger.Fatal(err.Error())
	}

	appLogger.Info("Start")
	handler := &sqsHandler{}
	handler.findingClient = newFindingClient(conf.FindingSvcAddr)
	handler.alertClient = newAlertClient(conf.AlertSvcAddr)
	handler.googleClient = newGoogleClient(conf.GoogleSvcAddr)
	handler.portscanClient = newPortscanClient(conf.GoogleCredentialPath, conf.ScanExcludePortNumber)

	sqsConf := &sqsConfig{
		Debug:              conf.Debug,
		AWSRegion:          conf.AWSRegion,
		SQSEndpoint:        conf.SQSEndpoint,
		PortscanQueueName:  conf.PortscanQueueName,
		PortscanQueueURL:   conf.PortscanQueueURL,
		MaxNumberOfMessage: conf.MaxNumberOfMessage,
		WaitTimeSecond:     conf.WaitTimeSecond,
	}
	consumer := newSQSConsumer(sqsConf)
	appLogger.Info("Start the SQS consumer server for GCP Portscan Service")
	ctx := context.Background()
	consumer.Start(ctx,
		mimosasqs.InitializeHandler(
			mimosasqs.RetryableErrorHandler(
				mimosasqs.StatusLoggingHandler(appLogger,
					mimosaxray.MessageTracingHandler(conf.EnvName, "google.portScan", handler)))))
}
