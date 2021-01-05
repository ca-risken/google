package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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
	cloudSploit   cloudSploitServiceClient
}

func newHandler() *sqsHandler {
	return &sqsHandler{
		findingClient: newFindingClient(),
		alertClient:   newAlertClient(),
		googleClient:  newGoogleClient(),
		cloudSploit:   newCloudSploitClient(),
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
	scanStatus := s.initScanStatus(gcp)

	// Get cloud sploit
	result, err := s.cloudSploit.run(ctx, gcp.GcpProjectId)
	if err != nil {
		appLogger.Errorf("Failed to run CloudSploit scan: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
			message.ProjectID, message.GCPID, message.GoogleDataSourceID, err)
		return err
	}
	for _, f := range *result {
		// Put finding
		if err := s.putFindings(ctx, message.ProjectID, gcp.GcpProjectId, &f); err != nil {
			appLogger.Errorf("Failed to put findngs: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
				message.ProjectID, message.GCPID, message.GoogleDataSourceID, err)
			return s.updateScanStatusError(ctx, scanStatus, err.Error())
		}
	}

	if err := s.updateScanStatusSuccess(ctx, scanStatus); err != nil {
		return err
	}
	return s.analyzeAlert(ctx, message.ProjectID)
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
		return nil, fmt.Errorf("No gcp data, project_id=%d, gcp_id=%d, google_data_source_Id=%d", projectID, gcpID, googleDataSourceID)
	}
	return data.GcpDataSource, nil
}

func (s *sqsHandler) initScanStatus(g *google.GCPDataSource) *google.AttachGCPDataSourceRequest {
	return &google.AttachGCPDataSourceRequest{
		ProjectId: g.ProjectId,
		GcpDataSource: &google.GCPDataSourceForUpsert{
			GcpId:              g.GcpId,
			GoogleDataSourceId: g.GoogleDataSourceId,
			ProjectId:          g.ProjectId,
			ScanAt:             time.Now().Unix(),
			Status:             google.Status_UNKNOWN, // After scan, will be updated
			StatusDetail:       "",
		},
	}
}

func (s *sqsHandler) putFindings(ctx context.Context, projectID uint32, gcpProjectID string, f *cloudSploitFinding) error {
	score := scoreCloudSploit(f)
	if score == 0.0 {
		// PutResource
		resp, err := s.findingClient.PutResource(ctx, &finding.PutResourceRequest{
			Resource: &finding.ResourceForUpsert{
				ResourceName: common.GetResourceName(gcpProjectID, f.Category, f.Resource),
				ProjectId:    projectID,
			},
		})
		if err != nil {
			appLogger.Errorf("Failed to put finding project_id=%d, resource=%s, err=%+v", projectID, f.Resource, err)
			return err
		}
		appLogger.Infof("Success to PutResource, finding_id=%d", resp.Resource.ResourceId)
		return nil
	}

	buf, err := json.Marshal(f)
	if err != nil {
		appLogger.Errorf("Failed to marshal user data, project_id=%d, resource=%s, err=%+v", projectID, f.Resource, err)
		return err
	}
	// PutFinding
	resp, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{
		Finding: &finding.FindingForUpsert{
			Description:      f.Description,
			DataSource:       common.AssetDataSource,
			DataSourceId:     f.DataSourceID,
			ResourceName:     common.GetResourceName(gcpProjectID, f.Category, common.GetShortName(f.Resource)),
			ProjectId:        projectID,
			OriginalScore:    score,
			OriginalMaxScore: 1.0,
			Data:             string(buf),
		},
	})
	if err != nil {
		appLogger.Errorf("Failed to put finding project_id=%d, resource=%s, err=%+v", projectID, f.Resource, err)
		return err
	}
	// PutFindingTag
	s.tagFinding(ctx, common.TagGCP, resp.Finding.FindingId, resp.Finding.ProjectId)
	s.tagFinding(ctx, common.TagCloudSploit, resp.Finding.FindingId, resp.Finding.ProjectId)
	s.tagFinding(ctx, strings.ToLower(f.Category), resp.Finding.FindingId, resp.Finding.ProjectId)
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

func (s *sqsHandler) updateScanStatusError(ctx context.Context, putData *google.AttachGCPDataSourceRequest, statusDetail string) error {
	putData.GcpDataSource.Status = google.Status_ERROR
	statusDetail = cutString(statusDetail, 200)
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
	appLogger.Infof("Success to update GCPDataSource status, response=%+v", resp)
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

func scoreCloudSploit(f *cloudSploitFinding) float32 {
	if strings.ToUpper(f.Status) == "OK" {
		return 0.0
	}
	if f.Resource == resourceUnknown {
		return 0.1
	}
	return 0.3
}
