package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/CyberAgent/mimosa-core/proto/alert"
	"github.com/CyberAgent/mimosa-core/proto/finding"
	"github.com/CyberAgent/mimosa-google/pkg/common"
	"github.com/CyberAgent/mimosa-google/proto/google"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
)

type sqsHandler struct {
	findingClient finding.FindingServiceClient
	alertClient   alert.AlertServiceClient
	googleClient  google.GoogleServiceClient
	gcpClient     gcpServiceClient
}

func newHandler() *sqsHandler {
	return &sqsHandler{
		findingClient: newFindingClient(),
		alertClient:   newAlertClient(),
		googleClient:  newGoogleClient(),
		gcpClient:     newGCPClient(),
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
	gcp, err := s.getGCP(ctx, message.ProjectID, message.GCPID)
	if err != nil {
		appLogger.Errorf("Failed to get gcp: project_id=%d, gcp_id=%d, err=%+v", message.ProjectID, message.GCPID, err)
		return err
	}
	scanStatus := s.initScanStatus(gcp)

	// Get cloud asset
	findings, err := s.gcpClient.listAsset(ctx, gcp)
	if err != nil {
		appLogger.Errorf("Failed to listAsset: project_id=%d, gcp_id=%d, err=%+v", message.ProjectID, message.GCPID, err)
		return s.updateScanStatusError(ctx, scanStatus, err.Error())
	}
	appLogger.Debugf("Got findings, count=%d, gcp_project=%s", len(*findings), gcp.GcpProjectId)

	for _, f := range *findings {
		// Put finding
		if err := s.putFindings(ctx, message.ProjectID, &f); err != nil {
			appLogger.Errorf("Failed to put findngs: project_id=%d, gcp_id=%d, err=%+v", message.ProjectID, message.GCPID, err)
			return s.updateScanStatusError(ctx, scanStatus, err.Error())
		}
	}
	if err := s.updateScanStatusSuccess(ctx, scanStatus); err != nil {
		return err
	}
	return s.analyzeAlert(ctx, message.ProjectID)
}

func (s *sqsHandler) getGCP(ctx context.Context, projectID, gcpID uint32) (*google.GCP, error) {
	data, err := s.googleClient.GetGCP(ctx, &google.GetGCPRequest{
		ProjectId: projectID,
		GcpId:     gcpID,
	})
	if err != nil {
		return nil, err
	}
	if data == nil || data.Gcp == nil {
		return nil, fmt.Errorf("No gcp data, project_id=%d, gcp_id=%d", projectID, gcpID)
	}
	return data.Gcp, nil
}

func (s *sqsHandler) initScanStatus(g *google.GCP) *google.PutGCPRequest {
	return &google.PutGCPRequest{
		ProjectId: g.ProjectId,
		Gcp: &google.GCPForUpsert{
			GcpId:              g.GcpId,
			GoogleDataSourceId: g.GoogleDataSourceId,
			Name:               g.Name,
			ProjectId:          g.ProjectId,
			GcpOrganizationId:  g.GcpOrganizationId,
			GcpProjectId:       g.GcpProjectId,
			ScanAt:             time.Now().Unix(),
			Status:             google.Status_UNKNOWN, // After scan, will be updated
			StatusDetail:       "",
		},
	}
}

func (s *sqsHandler) putFindings(ctx context.Context, projectID uint32, f *assetFinding) error {
	buf, err := json.Marshal(f)
	if err != nil {
		appLogger.Errorf("Failed to marshal user data, project_id=%d, assetName=%s, err=%+v", projectID, f.Name, err)
		return err
	}
	resp, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{
		Finding: &finding.FindingForUpsert{
			Description:      fmt.Sprintf("%s has been found by GCP Cloud Inventry", f.DisplayName),
			DataSource:       common.AssetDataSource,
			DataSourceId:     f.Name,
			ResourceName:     f.DisplayName,
			ProjectId:        projectID,
			OriginalScore:    scoreAsset(f),
			OriginalMaxScore: 1.0,
			Data:             string(buf),
		},
	})
	if err != nil {
		appLogger.Errorf("Failed to put finding project_id=%d, assetName=%s, err=%+v", projectID, f.Name, err)
		return err
	}
	// finding-tag
	s.tagFinding(ctx, common.TagGoogle, resp.Finding.FindingId, resp.Finding.ProjectId)
	s.tagFinding(ctx, common.TagGCP, resp.Finding.FindingId, resp.Finding.ProjectId)
	s.tagFinding(ctx, common.TagAssetInventory, resp.Finding.FindingId, resp.Finding.ProjectId)
	appLogger.Infof("Success to PutFinding, finding_id=%d", resp.Finding.FindingId)
	return nil
}

func (s *sqsHandler) tagFinding(ctx context.Context, tag string, findingID uint64, projectID uint32) error {
	_, err := s.findingClient.TagFinding(ctx, &finding.TagFindingRequest{
		ProjectId: projectID,
		Tag: &finding.FindingTagForUpsert{
			FindingId: findingID,
			ProjectId: projectID,
			Tag:       tag,
		}})
	if err != nil {
		appLogger.Errorf("Failed to TagFinding, finding_id=%d, tag=%s, error=%+v", findingID, tag, err)
		return err
	}
	return nil
}

func (s *sqsHandler) updateScanStatusError(ctx context.Context, putData *google.PutGCPRequest, statusDetail string) error {
	putData.Gcp.Status = google.Status_ERROR
	statusDetail = cutString(statusDetail, 200)
	putData.Gcp.StatusDetail = statusDetail
	return s.updateScanStatus(ctx, putData)
}

func (s *sqsHandler) updateScanStatusSuccess(ctx context.Context, putData *google.PutGCPRequest) error {
	putData.Gcp.Status = google.Status_OK
	putData.Gcp.StatusDetail = ""
	return s.updateScanStatus(ctx, putData)
}

func (s *sqsHandler) updateScanStatus(ctx context.Context, putData *google.PutGCPRequest) error {
	resp, err := s.googleClient.PutGCP(ctx, putData)
	if err != nil {
		return err
	}
	appLogger.Infof("Success to update AWS status, response=%+v", resp)
	return nil
}

func (s *sqsHandler) analyzeAlert(ctx context.Context, projectID uint32) error {
	_, err := s.alertClient.AnalyzeAlert(ctx, &alert.AnalyzeAlertRequest{
		ProjectId: projectID,
	})
	return err
}

func cutString(input string, cut int) string {
	if len(input) > cut {
		return input[:cut] + " ..." // cut long text
	}
	return input
}

func scoreAsset(f *assetFinding) float32 {
	return 0.1
}
