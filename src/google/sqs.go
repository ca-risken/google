package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-xray-sdk-go/xray"
	"github.com/ca-risken/google/pkg/common"
	"github.com/gassara-kys/envconfig"
)

type sqsConfig struct {
	AWSRegion   string `envconfig:"aws_region"   default:"ap-northeast-1"`
	SQSEndpoint string `envconfig:"sqs_endpoint" default:"http://queue.middleware.svc.cluster.local:9324"`

	AssetQueueURL       string `split_words:"true" required:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/google-asset"`
	CloudSploitQueueURL string `split_words:"true" required:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/google-cloudsploit"`
	SCCQueueURL         string `split_words:"true" required:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/google-scc"`
	PortscanQueueURL    string `split_words:"true" required:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/google-portscan"`
}

type sqsAPI interface {
	sendMsgForAsset(ctx context.Context, msg *common.GCPQueueMessage) (*sqs.SendMessageOutput, error)
	sendMsgForCloudSploit(ctx context.Context, msg *common.GCPQueueMessage) (*sqs.SendMessageOutput, error)
	sendMsgForSCC(ctx context.Context, msg *common.GCPQueueMessage) (*sqs.SendMessageOutput, error)
	sendMsgForPortscan(ctx context.Context, msg *common.GCPQueueMessage) (*sqs.SendMessageOutput, error)
}

type sqsClient struct {
	svc                 *sqs.SQS
	assetQueueURL       string
	cloudSploitQueueURL string
	sccQueueURL         string
	portscanQueueURL    string
}

func newSQSClient() *sqsClient {
	var conf sqsConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		appLogger.Fatalf("Failed to create a new session, %v", err)
	}
	session := sqs.New(sess, &aws.Config{
		Region:   &conf.AWSRegion,
		Endpoint: &conf.SQSEndpoint,
	})
	xray.AWS(session.Client)
	return &sqsClient{
		svc:                 session,
		assetQueueURL:       conf.AssetQueueURL,
		cloudSploitQueueURL: conf.CloudSploitQueueURL,
		sccQueueURL:         conf.SCCQueueURL,
		portscanQueueURL:    conf.PortscanQueueURL,
	}
}

func (s *sqsClient) sendMsgForAsset(ctx context.Context, msg *common.GCPQueueMessage) (*sqs.SendMessageOutput, error) {
	return s.sendMsgForGCP(ctx, s.assetQueueURL, msg)
}

func (s *sqsClient) sendMsgForCloudSploit(ctx context.Context, msg *common.GCPQueueMessage) (*sqs.SendMessageOutput, error) {
	return s.sendMsgForGCP(ctx, s.cloudSploitQueueURL, msg)
}

func (s *sqsClient) sendMsgForSCC(ctx context.Context, msg *common.GCPQueueMessage) (*sqs.SendMessageOutput, error) {
	return s.sendMsgForGCP(ctx, s.sccQueueURL, msg)
}

func (s *sqsClient) sendMsgForPortscan(ctx context.Context, msg *common.GCPQueueMessage) (*sqs.SendMessageOutput, error) {
	return s.sendMsgForGCP(ctx, s.portscanQueueURL, msg)
}

func (s *sqsClient) sendMsgForGCP(ctx context.Context, queueURL string, msg *common.GCPQueueMessage) (*sqs.SendMessageOutput, error) {
	buf, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse message, err=%+v", err)
	}
	resp, err := s.svc.SendMessageWithContext(ctx, &sqs.SendMessageInput{
		MessageBody:  aws.String(string(buf)),
		QueueUrl:     aws.String(queueURL),
		DelaySeconds: aws.Int64(1),
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}
