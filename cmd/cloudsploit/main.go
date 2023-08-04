package main

import (
	"context"
	"fmt"

	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/common/pkg/profiler"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	"github.com/ca-risken/common/pkg/tracer"
	"github.com/ca-risken/google/pkg/cloudsploit"
	"github.com/ca-risken/google/pkg/grpc"
	"github.com/ca-risken/google/pkg/sqs"
	"github.com/gassara-kys/envconfig"
)

const (
	nameSpace   = "google"
	serviceName = "cloudsploit"
	settingURL  = "https://docs.security-hub.jp/google/overview_gcp/"
)

var (
	appLogger            = logging.NewLogger()
	samplingRate float64 = 0.3000
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

	GoogleCloudSploitQueueName string `split_words:"true" default:"google-cloudsploit"`
	GoogleCloudSploitQueueURL  string `split_words:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/google-cloudsploit"`
	MaxNumberOfMessage         int32  `split_words:"true" default:"10"`
	WaitTimeSecond             int32  `split_words:"true" default:"20"`

	// grpc
	CoreSvcAddr          string `required:"true" split_words:"true" default:"core.core.svc.cluster.local:8080"`
	DataSourceAPISvcAddr string `required:"true" split_words:"true" default:"datasource-api.datasource.svc.cluster.local:8081"`

	// cloudsploit
	CloudSploitCommand             string `required:"true" split_words:"true" default:"/opt/cloudsploit/index.js"`
	GoogleServiceAccountEmail      string `required:"true" split_words:"true"`
	GoogleServiceAccountPrivateKey string `required:"true" split_words:"true"`
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
		ServiceName:  getFullServiceName(),
		Environment:  conf.EnvName,
		Debug:        conf.TraceDebug,
		SamplingRate: &samplingRate,
	}
	tracer.Start(tc)
	defer tracer.Stop()

	fc, err := grpc.NewFindingClient(conf.CoreSvcAddr)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create finding client, err=%+v", err)
	}
	ac, err := grpc.NewAlertClient(conf.CoreSvcAddr)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create alert client, err=%+v", err)
	}
	gc, err := grpc.NewGoogleClient(conf.DataSourceAPISvcAddr)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create google client, err=%+v", err)
	}
	cloudSploit := cloudsploit.NewCloudSploitClient(
		conf.CloudSploitCommand,
		conf.GoogleServiceAccountEmail,
		conf.GoogleServiceAccountPrivateKey,
		appLogger,
	)
	handler := cloudsploit.NewSqsHandler(
		fc,
		ac,
		gc,
		cloudSploit,
		appLogger,
	)

	appLogger.Info(ctx, "Start")
	sqsConf := &sqs.SQSConfig{
		Debug:              conf.Debug,
		AWSRegion:          conf.AWSRegion,
		SQSEndpoint:        conf.SQSEndpoint,
		QueueName:          conf.GoogleCloudSploitQueueName,
		QueueURL:           conf.GoogleCloudSploitQueueURL,
		MaxNumberOfMessage: conf.MaxNumberOfMessage,
		WaitTimeSecond:     conf.WaitTimeSecond,
	}
	consumer, err := sqs.NewSQSConsumer(ctx, sqsConf, appLogger)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create SQS consumer, err=%+v", err)
	}

	appLogger.Info(ctx, "Start the SQS consumer server for GCP CloudSploit...")
	consumer.Start(ctx,
		mimosasqs.InitializeHandler(
			mimosasqs.RetryableErrorHandler(
				mimosasqs.TracingHandler(getFullServiceName(),
					mimosasqs.StatusLoggingHandler(appLogger, handler)))))
}
