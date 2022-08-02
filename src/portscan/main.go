package main

import (
	"context"
	"fmt"

	"github.com/ca-risken/common/pkg/profiler"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	"github.com/ca-risken/common/pkg/tracer"
	"github.com/ca-risken/datasource-api/pkg/message"
	"github.com/gassara-kys/envconfig"
)

const (
	nameSpace   = "google"
	serviceName = "portscan"
	settingURL  = "https://docs.security-hub.jp/google/overview_gcp/"
)

func getFullServiceName() string {
	return fmt.Sprintf("%s.%s", nameSpace, serviceName)
}

type AppConfig struct {
	EnvName         string   `default:"local" split_words:"true"`
	ProfileExporter string   `split_words:"true" default:"nop"`
	ProfileTypes    []string `split_words:"true"`
	TraceDebug      bool     `split_words:"true" default:"false"`

	// sqs
	Debug string `default:"false"`

	AWSRegion   string `envconfig:"aws_region"   default:"ap-northeast-1"`
	SQSEndpoint string `envconfig:"sqs_endpoint" default:"http://queue.middleware.svc.cluster.local:9324"`

	GooglePortscanQueueName string `split_words:"true" default:"google-portscan"`
	GooglePortscanQueueURL  string `split_words:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/google-portscan"`
	MaxNumberOfMessage      int32  `split_words:"true" default:"10"`
	WaitTimeSecond          int32  `split_words:"true" default:"20"`

	// grpc
	CoreSvcAddr          string `required:"true" split_words:"true" default:"core.core.svc.cluster.local:8080"`
	DataSourceAPISvcAddr string `required:"true" split_words:"true" default:"datasource-api.core.svc.cluster.local:8081"`

	// portscan
	GoogleCredentialPath  string `required:"true" split_words:"true" default:"/tmp/credential.json"`
	ScanExcludePortNumber int    `split_words:"true"                 default:"1000"`
	ScanConcurrency       int64  `split_words:"true" default:"5"`
}

func main() {
	ctx := context.Background()
	var conf AppConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(ctx, err.Error())
	}

	pTypes, err := profiler.ConvertProfileTypeFrom(conf.ProfileTypes)
	if err != nil {
		appLogger.Fatal(ctx, err.Error())
	}
	pExporter, err := profiler.ConvertExporterTypeFrom(conf.ProfileExporter)
	if err != nil {
		appLogger.Fatal(ctx, err.Error())
	}
	pc := profiler.Config{
		ServiceName:  getFullServiceName(),
		EnvName:      conf.EnvName,
		ProfileTypes: pTypes,
		ExporterType: pExporter,
	}
	err = pc.Start()
	if err != nil {
		appLogger.Fatal(ctx, err.Error())
	}
	defer pc.Stop()

	tc := &tracer.Config{
		ServiceName: getFullServiceName(),
		Environment: conf.EnvName,
		Debug:       conf.TraceDebug,
	}
	tracer.Start(tc)
	defer tracer.Stop()

	appLogger.Info(ctx, "Start")
	findingClient, err := newFindingClient(conf.CoreSvcAddr)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create finding client, err=%+v", err)
	}
	alertClient, err := newAlertClient(conf.CoreSvcAddr)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create alert client, err=%+v", err)
	}
	googleClient, err := newGoogleClient(conf.DataSourceAPISvcAddr)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create google client, err=%+v", err)
	}
	portscanClient, err := newPortscanClient(conf.GoogleCredentialPath, conf.ScanExcludePortNumber)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create portscan client, err=%+v", err)
	}
	handler := &sqsHandler{
		findingClient:   findingClient,
		alertClient:     alertClient,
		googleClient:    googleClient,
		portscanClient:  portscanClient,
		scanConcurrency: conf.ScanConcurrency,
	}
	f, err := mimosasqs.NewFinalizer(message.GooglePortscanDataSource, settingURL, conf.CoreSvcAddr, nil)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create Finalizer, err=%+v", err)
	}

	sqsConf := &SQSConfig{
		Debug:              conf.Debug,
		AWSRegion:          conf.AWSRegion,
		SQSEndpoint:        conf.SQSEndpoint,
		QueueName:          conf.GooglePortscanQueueName,
		QueueURL:           conf.GooglePortscanQueueURL,
		MaxNumberOfMessage: conf.MaxNumberOfMessage,
		WaitTimeSecond:     conf.WaitTimeSecond,
	}
	consumer, err := newSQSConsumer(ctx, sqsConf)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create SQS consumer, err=%+v", err)
	}
	appLogger.Info(ctx, "Start the SQS consumer server for GCP Portscan Service")
	consumer.Start(ctx,
		mimosasqs.InitializeHandler(
			mimosasqs.RetryableErrorHandler(
				mimosasqs.TracingHandler(getFullServiceName(),
					mimosasqs.StatusLoggingHandler(appLogger,
						f.FinalizeHandler(handler))))))
}
