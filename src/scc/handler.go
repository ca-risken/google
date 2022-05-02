package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-xray-sdk-go/xray"
	"github.com/ca-risken/common/pkg/grpc_client"
	"github.com/ca-risken/common/pkg/logging"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	"github.com/ca-risken/core/proto/alert"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/google/pkg/common"
	"github.com/ca-risken/google/proto/google"
	sccpb "google.golang.org/genproto/googleapis/cloud/securitycenter/v1"
)

type sqsHandler struct {
	findingClient finding.FindingServiceClient
	alertClient   alert.AlertServiceClient
	googleClient  google.GoogleServiceClient
	sccClient     sccServiceClient
}

func (s *sqsHandler) HandleMessage(ctx context.Context, sqsMsg *sqs.Message) error {
	msgBody := aws.StringValue(sqsMsg.Body)
	appLogger.Infof("got message: %s", msgBody)
	msg, err := common.ParseMessage(msgBody)
	if err != nil {
		appLogger.Errorf("Invalid message: msg=%+v, err=%+v", msgBody, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	requestID, err := appLogger.GenerateRequestID(fmt.Sprint(msg.ProjectID))
	if err != nil {
		appLogger.Warnf("Failed to generate requestID: err=%+v", err)
		requestID = fmt.Sprint(msg.ProjectID)
	}

	appLogger.Infof("start SCC scan, RequestID=%s", requestID)
	gcp, err := s.getGCPDataSource(ctx, msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID)
	if err != nil {
		appLogger.Errorf("Failed to get gcp: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
			msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	scanStatus := common.InitScanStatus(gcp)

	// Get security command center
	if gcp.GcpOrganizationId == "" || gcp.GcpProjectId == "" {
		err := fmt.Errorf("Required GcpOrganizationId and GcpProjectId parameters, GcpOrganizationId=%s, GcpProjectId=%s",
			gcp.GcpOrganizationId, gcp.GcpProjectId)
		appLogger.Errorf("Invalid parameters, project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
			msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, err)
		return s.handleErrorWithUpdateStatus(ctx, scanStatus, err)
	}
	appLogger.Infof("start SCC ListFinding API, RequestID=%s", requestID)
	xctx, segment := xray.BeginSubsegment(ctx, "listFinding")
	it := s.sccClient.listFinding(xctx, gcp.GcpOrganizationId, gcp.GcpProjectId)
	segment.Close(nil)
	appLogger.Infof("end SCC ListFinding API, RequestID=%s", requestID)

	appLogger.Infof("start put findings, RequestID=%s", requestID)
	nextPageToken := ""
	counter := 0
	for {
		findings, token, err := it.InternalFetch(finding.PutFindingBatchMaxLength, nextPageToken)
		if err != nil {
			appLogger.Errorf("Failed to Coud SCC API: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
				msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, err)
			return s.handleErrorWithUpdateStatus(ctx, scanStatus, err)
		}
		findingBatchParam := []*finding.FindingBatchForUpsert{}
		for _, f := range findings {
			data, err := s.generateFindingData(msg.ProjectID, gcp.GcpProjectId, f.Finding)
			if err != nil {
				return s.handleErrorWithUpdateStatus(ctx, scanStatus, err)
			}
			findingBatchParam = append(findingBatchParam, data)
		}
		if len(findingBatchParam) > 0 {
			if err := grpc_client.PutFindingBatch(ctx, s.findingClient, msg.ProjectID, findingBatchParam); err != nil {
				return err
			}
		}
		counter = counter + len(findingBatchParam)
		if token == "" {
			break
		}
		nextPageToken = token
	}
	appLogger.Infof("end put findings(%d succeeded), RequestID=%s", counter, requestID)

	if err := s.updateScanStatusSuccess(ctx, scanStatus); err != nil {
		return mimosasqs.WrapNonRetryable(err)
	}
	appLogger.Infof("end SCC scan, RequestID=%s", requestID)
	if msg.ScanOnly {
		return nil
	}
	if err := s.analyzeAlert(ctx, msg.ProjectID); err != nil {
		appLogger.Notifyf(logging.ErrorLevel, "Failed to analyzeAlert, project_id=%d, err=%+v", msg.ProjectID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	return nil
}

func (s *sqsHandler) handleErrorWithUpdateStatus(ctx context.Context, scanStatus *google.AttachGCPDataSourceRequest, err error) error {
	if updateErr := s.updateScanStatusError(ctx, scanStatus, err.Error()); updateErr != nil {
		appLogger.Warnf("Failed to update scan status error: err=%+v", updateErr)
	}
	return mimosasqs.WrapNonRetryable(err)
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

func (s *sqsHandler) generateFindingData(projectID uint32, gcpProjectID string, f *sccpb.Finding) (*finding.FindingBatchForUpsert, error) {
	buf, err := json.Marshal(f)
	if err != nil {
		appLogger.Errorf("Failed to marshal user data, project_id=%d, findingName=%s, err=%+v", projectID, f.Name, err)
		return nil, err
	}
	findingData := &finding.FindingBatchForUpsert{
		Finding: &finding.FindingForUpsert{
			Description:      fmt.Sprintf("Security Command Center: %s", f.Category),
			DataSource:       common.SCCDataSource,
			DataSourceId:     f.Name,
			ResourceName:     f.ResourceName,
			ProjectId:        projectID,
			OriginalScore:    scoreSCC(f),
			OriginalMaxScore: 1.0,
			Data:             string(buf),
		},
		Tag: []*finding.FindingTagForBatch{
			{Tag: common.TagGoogle},
			{Tag: common.TagGCP},
			{Tag: common.TagSCC},
			{Tag: gcpProjectID},
			{Tag: common.GetServiceName(f.ResourceName)},
		},
	}
	if f.Category != "" && f.SourceProperties["Explanation"] != nil && f.SourceProperties["Explanation"].GetStringValue() != "" {
		findingData.Recommend = &finding.RecommendForBatch{
			Type:           f.Category,
			Risk:           f.SourceProperties["Explanation"].GetStringValue(),
			Recommendation: "Please see the finding JSON data in 'data.source_properties.Recommendation'",
		}
	}
	return findingData, nil
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
