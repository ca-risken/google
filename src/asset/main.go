package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-xray-sdk-go/xray"
	"github.com/ca-risken/common/pkg/profiler"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	mimosaxray "github.com/ca-risken/common/pkg/xray"
	"github.com/ca-risken/google/pkg/common"
	"github.com/gassara-kys/envconfig"
)

const (
	nameSpace   = "google"
	serviceName = "asset"
	settingURL  = "https://docs.security-hub.jp/google/overview_gcp/"
)

func getFullServiceName() string {
	return fmt.Sprintf("%s.%s", nameSpace, serviceName)
}

type AppConfig struct {
	EnvName         string   `default:"local" split_words:"true"`
	ProfileExporter string   `split_words:"true" default:"nop"`
	ProfileTypes    []string `split_words:"true"`

	// asset
	GoogleCredentialPath string `required:"true" split_words:"true" default:"/tmp/credential.json"`

	// grpc
	FindingSvcAddr string `required:"true" split_words:"true" default:"finding.core.svc.cluster.local:8001"`
	AlertSvcAddr   string `required:"true" split_words:"true" default:"alert.core.svc.cluster.local:8004"`
	GoogleSvcAddr  string `required:"true" split_words:"true" default:"google.google.svc.cluster.local:11001"`

	// sqs
	Debug string `default:"false"`

	AWSRegion   string `envconfig:"aws_region"   default:"ap-northeast-1"`
	SQSEndpoint string `envconfig:"sqs_endpoint" default:"http://queue.middleware.svc.cluster.local:9324"`

	AssetQueueName     string `split_words:"true" default:"google-asset"`
	AssetQueueURL      string `split_words:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/google-asset"`
	MaxNumberOfMessage int64  `split_words:"true" default:"10"`
	WaitTimeSecond     int64  `split_words:"true" default:"20"`

	// handler
	WaitMilliSecPerRequest int `split_words:"true" default:"500"`
	AssetAPIRetryNum       int `split_words:"true" default:"3"`
	AssetAPIRetryWaitSec   int `split_words:"true" default:"30"`
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

	pTypes, err := profiler.ConvertProfileTypeFrom(conf.ProfileTypes)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	pExporter, err := profiler.ConvertExporterTypeFrom(conf.ProfileExporter)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	pc := profiler.Config{
		ServiceName:  getFullServiceName(),
		EnvName:      conf.EnvName,
		ProfileTypes: pTypes,
		ExporterType: pExporter,
	}
	err = pc.Start()
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	defer pc.Stop()

	appLogger.Info("Start")
	handler := &sqsHandler{
		waitMilliSecPerRequest: conf.WaitMilliSecPerRequest,
		assetAPIRetryNum:       conf.AssetAPIRetryNum,
		assetAPIRetryWaitSec:   conf.AssetAPIRetryWaitSec,
	}
	handler.findingClient = newFindingClient(conf.FindingSvcAddr)
	handler.alertClient = newAlertClient(conf.AlertSvcAddr)
	handler.googleClient = newGoogleClient(conf.GoogleSvcAddr)
	handler.assetClient = newAssetClient(conf.GoogleCredentialPath)
	f, err := mimosasqs.NewFinalizer(common.AssetDataSource, settingURL, conf.FindingSvcAddr, nil)
	if err != nil {
		appLogger.Fatalf("Failed to create Finalizer, err=%+v", err)
	}

	sqsConf := &SQSConfig{
		Debug:              conf.Debug,
		AWSRegion:          conf.AWSRegion,
		SQSEndpoint:        conf.SQSEndpoint,
		AssetQueueName:     conf.AssetQueueName,
		AssetQueueURL:      conf.AssetQueueURL,
		MaxNumberOfMessage: conf.MaxNumberOfMessage,
		WaitTimeSecond:     conf.WaitTimeSecond,
	}
	consumer := newSQSConsumer(sqsConf)
	appLogger.Info("Start the SQS consumer server for GCP Cloud Asset Inventory...")
	ctx := context.Background()
	consumer.Start(ctx,
		mimosasqs.InitializeHandler(
			mimosasqs.RetryableErrorHandler(
				mimosasqs.StatusLoggingHandler(appLogger,
					mimosaxray.MessageTracingHandler(conf.EnvName, getFullServiceName(),
						f.FinalizeHandler(handler))))))
}
