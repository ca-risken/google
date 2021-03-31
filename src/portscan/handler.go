package main

import (
	"context"
	"fmt"

	"github.com/CyberAgent/mimosa-core/proto/alert"
	"github.com/CyberAgent/mimosa-core/proto/finding"
	"github.com/CyberAgent/mimosa-google/pkg/common"
	"github.com/CyberAgent/mimosa-google/proto/google"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
)

type sqsHandler struct {
	findingClient  finding.FindingServiceClient
	alertClient    alert.AlertServiceClient
	googleClient   google.GoogleServiceClient
	portscanClient portscanServiceClient
}

func newHandler() *sqsHandler {
	return &sqsHandler{
		findingClient:  newFindingClient(),
		alertClient:    newAlertClient(),
		googleClient:   newGoogleClient(),
		portscanClient: newPortscanClient(),
	}
}

func (s *sqsHandler) HandleMessage(msg *sqs.Message) error {
	msgBody := aws.StringValue(msg.Body)
	appLogger.Infof("got message: %s", msgBody)
	message, err := common.ParseMessage(msgBody)
	if err != nil {
		appLogger.Errorf("Invalid message: msg=%+v, err=%+v", msg, err)
		return err
	}

	ctx := context.Background()
	gcp, err := s.getGCPDataSource(ctx, message.ProjectID, message.GCPID, message.GoogleDataSourceID)
	if err != nil {
		appLogger.Errorf("Failed to get gcp: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
			message.ProjectID, message.GCPID, message.GoogleDataSourceID, err)
		return err
	}
	scanStatus := common.InitScanStatus(gcp)

	// get target and scan target
	findings, err := s.scan(ctx, gcp.GcpProjectId, message)
	if err != nil {
		return s.updateScanStatusError(ctx, scanStatus, err.Error())
	}
	if err := s.putFindings(ctx, findings); err != nil {
		appLogger.Errorf("Failed put findings. err: %v", err)
		return err
	}

	if err := s.updateScanStatusSuccess(ctx, scanStatus); err != nil {
		return err
	}

	return s.analyzeAlert(ctx, message.ProjectID)
}

func (s *sqsHandler) scan(ctx context.Context, gcpProjectId string, message *common.GCPQueueMessage) ([]*finding.FindingForUpsert, error) {
	targets, err := s.portscanClient.listTarget(ctx, gcpProjectId)
	if err != nil {
		return nil, err
	}
	targets, excludeList := s.portscanClient.excludeTarget(targets)
	var findings []*finding.FindingForUpsert
	for _, target := range targets {
		results := scanTarget(target)
		for _, result := range results {
			finding, err := makeFinding(result, message)
			if err != nil {
				appLogger.Errorf("Failed making Finding err: %v", err)
			}
			findings = append(findings, finding)
		}
	}
	for _, exclude := range excludeList {
		finding, err := makeExcludeFinding(exclude, message)
		if err != nil {
			appLogger.Errorf("Failed making exclude Finding err: %v", err)
		}
		findings = append(findings, finding)
	}
	return findings, nil
}

func (s *sqsHandler) getGCPDataSource(ctx context.Context, projectID, gcpID, googleDataSourceID uint32) (*google.GCPDataSource, error) {
	data, err := s.googleClient.GetGCPDataSource(ctx, &google.GetGCPDataSourceRequest{
		ProjectId:          projectID,
		GcpId:              gcpID,
		GoogleDataSourceId: googleDataSourceID,
	})
	if err != nil {
		return nil, err
	}
	if data == nil || data.GcpDataSource == nil {
		return nil, fmt.Errorf("No gcp data, project_id=%d, gcp_id=%d, google_data_source_id=%d", projectID, gcpID, googleDataSourceID)
	}
	return data.GcpDataSource, nil
}

func (s *sqsHandler) updateScanStatusError(ctx context.Context, putData *google.AttachGCPDataSourceRequest, statusDetail string) error {
	putData.GcpDataSource.Status = google.Status_ERROR
	statusDetail = common.CutString(statusDetail, 200)
	putData.GcpDataSource.StatusDetail = statusDetail
	return s.updateScanStatus(ctx, putData)
}

func (s *sqsHandler) updateScanStatusSuccess(ctx context.Context, putData *google.AttachGCPDataSourceRequest) error {
	putData.GcpDataSource.Status = google.Status_OK
	putData.GcpDataSource.StatusDetail = ""
	return s.updateScanStatus(ctx, putData)
}

func (s *sqsHandler) updateScanStatus(ctx context.Context, putData *google.AttachGCPDataSourceRequest) error {
	resp, err := s.googleClient.AttachGCPDataSource(ctx, putData)
	if err != nil {
		return err
	}
	appLogger.Infof("Success to update GCP DataSource status, response=%+v", resp)
	return nil
}

func (s *sqsHandler) analyzeAlert(ctx context.Context, projectID uint32) error {
	_, err := s.alertClient.AnalyzeAlert(ctx, &alert.AnalyzeAlertRequest{
		ProjectId: projectID,
	})
	return err
}

type excludeResult struct {
	FromPort         int
	ToPort           int
	Protocol         string
	Target           string
	ResourceName     string
	FirewallRuleName string
}
