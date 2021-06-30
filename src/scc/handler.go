package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/CyberAgent/mimosa-common/pkg/logging"
	"github.com/CyberAgent/mimosa-core/proto/alert"
	"github.com/CyberAgent/mimosa-core/proto/finding"
	"github.com/CyberAgent/mimosa-google/pkg/common"
	"github.com/CyberAgent/mimosa-google/proto/google"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"google.golang.org/api/iterator"
	sccpb "google.golang.org/genproto/googleapis/cloud/securitycenter/v1"
)

type sqsHandler struct {
	findingClient finding.FindingServiceClient
	alertClient   alert.AlertServiceClient
	googleClient  google.GoogleServiceClient
	sccClient     sccServiceClient
}

func newHandler() *sqsHandler {
	return &sqsHandler{
		findingClient: newFindingClient(),
		alertClient:   newAlertClient(),
		googleClient:  newGoogleClient(),
		sccClient:     newSCCClient(),
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
	requestID, err := logging.GenerateRequestID(fmt.Sprint(message.ProjectID))
	if err != nil {
		appLogger.Warnf("Failed to generate requestID: err=%+v", err)
		requestID = fmt.Sprint(message.ProjectID)
	}

	appLogger.Infof("start SCC scan, RequestID=%s", requestID)
	ctx := context.Background()
	appLogger.Infof("start getGCPDataSource, RequestID=%s", requestID)
	gcp, err := s.getGCPDataSource(ctx, message.ProjectID, message.GCPID, message.GoogleDataSourceID)
	if err != nil {
		appLogger.Errorf("Failed to get gcp: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
			message.ProjectID, message.GCPID, message.GoogleDataSourceID, err)
		return err
	}
	appLogger.Infof("end getGCPDataSource, RequestID=%s", requestID)
	scanStatus := common.InitScanStatus(gcp)

	// Get security command center
	if gcp.GcpOrganizationId == "" || gcp.GcpProjectId == "" {
		err := fmt.Errorf("Required GcpOrganizationId and GcpProjectId parameters, GcpOrganizationId=%s, GcpProjectId=%s",
			gcp.GcpOrganizationId, gcp.GcpProjectId)
		appLogger.Errorf("Invalid parameters, project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
			message.ProjectID, message.GCPID, message.GoogleDataSourceID, err)
		return s.updateScanStatusError(ctx, scanStatus, err.Error())
	}
	appLogger.Infof("start SCC ListFinding API, RequestID=%s", requestID)
	it := s.sccClient.listFinding(ctx, gcp.GcpOrganizationId, gcp.GcpProjectId)
	appLogger.Infof("end SCC ListFinding API, RequestID=%s", requestID)

	appLogger.Infof("start putFindings, RequestID=%s", requestID)
	findingCnt := 0
	for {
		f, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			appLogger.Errorf("Failed to Coud SCC API: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
				message.ProjectID, message.GCPID, message.GoogleDataSourceID, err)
			return s.updateScanStatusError(ctx, scanStatus, err.Error())
		}
		appLogger.Debugf("Got finding: %+v", f.Finding)
		// Put finding
		if err := s.putFindings(ctx, message.ProjectID, gcp.GcpProjectId, f.Finding); err != nil {
			appLogger.Errorf("Failed to put findngs: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
				message.ProjectID, message.GCPID, message.GoogleDataSourceID, err)
			return s.updateScanStatusError(ctx, scanStatus, err.Error())
		}
		findingCnt++
	}
	appLogger.Infof("Got %d findings, RequestID=%s", findingCnt, requestID)
	appLogger.Infof("end putFindings, RequestID=%s", requestID)

	appLogger.Infof("start update scan status, RequestID=%s", requestID)
	if err := s.updateScanStatusSuccess(ctx, scanStatus); err != nil {
		return err
	}
	appLogger.Infof("end update scan status, RequestID=%s", requestID)

	appLogger.Infof("end SCC scan, RequestID=%s", requestID)
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
		return nil, fmt.Errorf("No gcp data, project_id=%d, gcp_id=%d, google_data_source_id=%d", projectID, gcpID, googleDataSourceID)
	}
	return data.GcpDataSource, nil
}

func (s *sqsHandler) putFindings(ctx context.Context, projectID uint32, gcpProjectID string, f *sccpb.Finding) error {
	buf, err := json.Marshal(f)
	if err != nil {
		appLogger.Errorf("Failed to marshal user data, project_id=%d, findingName=%s, err=%+v", projectID, f.Name, err)
		return err
	}
	// PutFinding
	resp, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{
		Finding: &finding.FindingForUpsert{
			Description:      fmt.Sprintf("Security Command Center: %s", f.Category),
			DataSource:       common.SCCDataSource,
			DataSourceId:     f.Name,
			ResourceName:     common.GetShortResourceName(gcpProjectID, f.ResourceName),
			ProjectId:        projectID,
			OriginalScore:    scoreSCC(f),
			OriginalMaxScore: 1.0,
			Data:             string(buf),
		},
	})
	if err != nil {
		appLogger.Errorf("Failed to put finding project_id=%d, SCCName=%s, err=%+v", projectID, f.Name, err)
		return err
	}
	// PutFindingTag
	s.tagFinding(ctx, common.TagGCP, resp.Finding.FindingId, resp.Finding.ProjectId)
	s.tagFinding(ctx, common.TagSCC, resp.Finding.FindingId, resp.Finding.ProjectId)
	s.tagFinding(ctx, gcpProjectID, resp.Finding.FindingId, resp.Finding.ProjectId)
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
