package scc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/ca-risken/common/pkg/grpc_client"
	"github.com/ca-risken/common/pkg/logging"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	"github.com/ca-risken/core/proto/alert"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/datasource-api/pkg/message"
	"github.com/ca-risken/datasource-api/proto/google"
	"github.com/ca-risken/google/pkg/common"
	sccpb "google.golang.org/genproto/googleapis/cloud/securitycenter/v1"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

type SqsHandler struct {
	findingClient finding.FindingServiceClient
	alertClient   alert.AlertServiceClient
	googleClient  google.GoogleServiceClient
	sccClient     SCCServiceClient
	logger        logging.Logger
}

func NewSqsHandler(
	fc finding.FindingServiceClient,
	ac alert.AlertServiceClient,
	gc google.GoogleServiceClient,
	sccc SCCServiceClient,
	l logging.Logger,
) *SqsHandler {
	return &SqsHandler{
		findingClient: fc,
		alertClient:   ac,
		googleClient:  gc,
		sccClient:     sccc,
		logger:        l,
	}
}

func (s *SqsHandler) HandleMessage(ctx context.Context, sqsMsg *types.Message) error {
	msgBody := aws.ToString(sqsMsg.Body)
	s.logger.Infof(ctx, "got message: %s", msgBody)
	msg, err := message.ParseMessageGCP(msgBody)
	if err != nil {
		s.logger.Errorf(ctx, "invalid message: msg=%+v, err=%+v", msgBody, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	requestID, err := s.logger.GenerateRequestID(fmt.Sprint(msg.ProjectID))
	if err != nil {
		s.logger.Warnf(ctx, "failed to generate requestID: err=%+v", err)
		requestID = fmt.Sprint(msg.ProjectID)
	}

	s.logger.Infof(ctx, "start SCC scan, RequestID=%s", requestID)
	gcp, err := s.getGCPDataSource(ctx, msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID)
	if err != nil {
		s.logger.Errorf(ctx, "failed to get gcp: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
			msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	scanStatus := common.InitScanStatus(gcp)

	// Get security command center
	if gcp.GcpOrganizationId == "" || gcp.GcpProjectId == "" {
		err := fmt.Errorf("Required GcpOrganizationId and GcpProjectId parameters, GcpOrganizationId=%s, GcpProjectId=%s",
			gcp.GcpOrganizationId, gcp.GcpProjectId)
		s.logger.Errorf(ctx, "Invalid parameters, project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
			msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, err)
		s.updateStatusToError(ctx, scanStatus, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	s.logger.Infof(ctx, "start SCC ListFinding API, RequestID=%s", requestID)
	tspan, tctx := tracer.StartSpanFromContext(ctx, "listFinding")
	it := s.sccClient.listFinding(tctx, gcp.GcpOrganizationId, gcp.GcpProjectId)
	tspan.Finish()
	s.logger.Infof(ctx, "end SCC ListFinding API, RequestID=%s", requestID)

	s.logger.Infof(ctx, "start put findings, RequestID=%s", requestID)
	nextPageToken := ""
	counter := 0
	for {
		findings, token, err := it.InternalFetch(finding.PutFindingBatchMaxLength, nextPageToken)
		if err != nil {
			s.logger.Errorf(ctx, "failed to Coud SCC API: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
				msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, err)
			s.updateStatusToError(ctx, scanStatus, err)
			return mimosasqs.WrapNonRetryable(err)
		}
		findingBatchParam := []*finding.FindingBatchForUpsert{}
		for _, f := range findings {
			data, err := s.generateFindingData(ctx, msg.ProjectID, gcp.GcpProjectId, f.Finding)
			if err != nil {
				s.updateStatusToError(ctx, scanStatus, err)
				return mimosasqs.WrapNonRetryable(err)
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
	s.logger.Infof(ctx, "end put findings(%d succeeded), RequestID=%s", counter, requestID)

	if err := s.updateScanStatusSuccess(ctx, scanStatus); err != nil {
		return mimosasqs.WrapNonRetryable(err)
	}
	s.logger.Infof(ctx, "end SCC scan, RequestID=%s", requestID)
	if msg.ScanOnly {
		return nil
	}
	if err := s.analyzeAlert(ctx, msg.ProjectID); err != nil {
		s.logger.Notifyf(ctx, logging.ErrorLevel, "failed to analyzeAlert, project_id=%d, err=%+v", msg.ProjectID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	return nil
}

func (s *SqsHandler) updateStatusToError(ctx context.Context, scanStatus *google.AttachGCPDataSourceRequest, err error) {
	if updateErr := s.updateScanStatusError(ctx, scanStatus, err.Error()); updateErr != nil {
		s.logger.Warnf(ctx, "failed to update scan status error: err=%+v", updateErr)
	}
}

func (s *SqsHandler) getGCPDataSource(ctx context.Context, projectID, gcpID, googleDataSourceID uint32) (*google.GCPDataSource, error) {
	data, err := s.googleClient.GetGCPDataSource(ctx, &google.GetGCPDataSourceRequest{
		ProjectId:          projectID,
		GcpId:              gcpID,
		GoogleDataSourceId: googleDataSourceID,
	})
	if err != nil {
		return nil, err
	}
	if data == nil || data.GcpDataSource == nil {
		return nil, fmt.Errorf("no gcp data, project_id=%d, gcp_id=%d, google_data_source_id=%d", projectID, gcpID, googleDataSourceID)
	}
	return data.GcpDataSource, nil
}

func (s *SqsHandler) generateFindingData(ctx context.Context, projectID uint32, gcpProjectID string, f *sccpb.Finding) (*finding.FindingBatchForUpsert, error) {
	buf, err := json.Marshal(f)
	if err != nil {
		s.logger.Errorf(ctx, "failed to marshal user data, project_id=%d, findingName=%s, err=%+v", projectID, f.Name, err)
		return nil, err
	}
	findingData := &finding.FindingBatchForUpsert{
		Finding: &finding.FindingForUpsert{
			Description:      fmt.Sprintf("Security Command Center: %s", f.Category),
			DataSource:       message.GoogleSCCDataSource,
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

func (s *SqsHandler) updateScanStatusError(ctx context.Context, putData *google.AttachGCPDataSourceRequest, statusDetail string) error {
	putData.GcpDataSource.Status = google.Status_ERROR
	statusDetail = common.CutString(statusDetail, 200)
	putData.GcpDataSource.StatusDetail = statusDetail
	return s.updateScanStatus(ctx, putData)
}

func (s *SqsHandler) updateScanStatusSuccess(ctx context.Context, putData *google.AttachGCPDataSourceRequest) error {
	putData.GcpDataSource.Status = google.Status_OK
	putData.GcpDataSource.StatusDetail = ""
	return s.updateScanStatus(ctx, putData)
}

func (s *SqsHandler) updateScanStatus(ctx context.Context, putData *google.AttachGCPDataSourceRequest) error {
	resp, err := s.googleClient.AttachGCPDataSource(ctx, putData)
	if err != nil {
		return err
	}
	s.logger.Infof(ctx, "success to update GCP DataSource status, response=%+v", resp)
	return nil
}

func (s *SqsHandler) analyzeAlert(ctx context.Context, projectID uint32) error {
	_, err := s.alertClient.AnalyzeAlert(ctx, &alert.AnalyzeAlertRequest{
		ProjectId: projectID,
	})
	return err
}