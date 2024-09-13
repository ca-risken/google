package cloudsploit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/ca-risken/common/pkg/logging"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	"github.com/ca-risken/core/proto/alert"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/datasource-api/pkg/message"
	"github.com/ca-risken/datasource-api/proto/google"
	"github.com/ca-risken/google/pkg/common"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

type SqsHandler struct {
	findingClient finding.FindingServiceClient
	alertClient   alert.AlertServiceClient
	googleClient  google.GoogleServiceClient
	cloudSploit   cloudSploitServiceClient
	logger        logging.Logger
}

func NewSqsHandler(
	fc finding.FindingServiceClient,
	ac alert.AlertServiceClient,
	gc google.GoogleServiceClient,
	cloudSploit *CloudSploitClient,
	l logging.Logger,
) *SqsHandler {
	return &SqsHandler{
		findingClient: fc,
		alertClient:   ac,
		googleClient:  gc,
		cloudSploit:   cloudSploit,
		logger:        l,
	}
}

func (s *SqsHandler) HandleMessage(ctx context.Context, sqsMsg *types.Message) error {
	msgBody := aws.ToString(sqsMsg.Body)
	s.logger.Infof(ctx, "got message: %s", msgBody)
	msg, err := message.ParseMessageGCP(msgBody)
	if err != nil {
		s.logger.Errorf(ctx, "Invalid message: msg=%+v, err=%+v", sqsMsg, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	beforeScanAt := time.Now()
	requestID, err := s.logger.GenerateRequestID(fmt.Sprint(msg.ProjectID))
	if err != nil {
		s.logger.Warnf(ctx, "Failed to generate requestID: err=%+v", err)
		requestID = fmt.Sprint(msg.ProjectID)
	}

	s.logger.Infof(ctx, "start CloudSploit scan, RequestID=%s", requestID)
	s.logger.Infof(ctx, "start getGCPDataSource, RequestID=%s", requestID)
	gcp, err := s.getGCPDataSource(ctx, msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID)
	if err != nil {
		s.logger.Errorf(ctx, "Failed to get gcp: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
			msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	s.logger.Infof(ctx, "end getGCPDataSource, RequestID=%s", requestID)
	scanStatus := common.InitScanStatus(gcp)

	// Get cloud sploit
	s.logger.Infof(ctx, "start Run cloudsploit, RequestID=%s", requestID)
	tspan, tctx := tracer.StartSpanFromContext(ctx, "runCloudSploit")
	result, err := s.cloudSploit.run(tctx, gcp.GcpProjectId)
	tspan.Finish(tracer.WithError(err))
	s.logger.Infof(ctx, "end Run cloudsploit, RequestID=%s", requestID)
	if err != nil {
		err = fmt.Errorf("failed to run CloudSploit scan: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%w",
			msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, err)
		s.logger.Error(ctx, err)
		s.updateStatusToError(ctx, scanStatus, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	s.logger.Infof(ctx, "start put finding, RequestID=%s", requestID)

	for _, f := range result {
		// Put finding
		if err := s.putFindings(ctx, msg.ProjectID, gcp.GcpProjectId, f); err != nil {
			errMsg := fmt.Sprintf("Failed to put findngs: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
				msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, err)
			s.logger.Error(ctx, errMsg)
			s.updateStatusToError(ctx, scanStatus, err)
			return mimosasqs.WrapNonRetryable(err)
		}
	}
	s.logger.Infof(ctx, "end put finding, RequestID=%s", requestID)

	// Clear score for inactive findings
	if _, err := s.findingClient.ClearScore(ctx, &finding.ClearScoreRequest{
		DataSource: message.GoogleCloudSploitDataSource,
		ProjectId:  msg.ProjectID,
		Tag:        []string{gcp.GcpProjectId},
		BeforeAt:   beforeScanAt.Unix(),
	}); err != nil {
		s.logger.Errorf(ctx, "Failed to clear finding score. GcpProjectID: %v, error: %v", gcp.GcpProjectId, err)
		s.updateStatusToError(ctx, scanStatus, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	s.logger.Infof(ctx, "start update scan status, RequestID=%s", requestID)
	if err := s.updateScanStatusSuccess(ctx, scanStatus, unknownFindings(result)); err != nil {
		return mimosasqs.WrapNonRetryable(err)
	}
	s.logger.Infof(ctx, "end update scan status, RequestID=%s", requestID)
	s.logger.Infof(ctx, "end CloudSploit scan, RequestID=%s", requestID)
	if msg.ScanOnly {
		return nil
	}
	if err := s.analyzeAlert(ctx, msg.ProjectID); err != nil {
		s.logger.Notifyf(ctx, logging.ErrorLevel, "Failed to analyzeAlert, project_id=%d, err=%+v", msg.ProjectID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	return nil
}

func (s *SqsHandler) updateStatusToError(ctx context.Context, scanStatus *google.AttachGCPDataSourceRequest, err error) {
	if updateErr := s.updateScanStatusError(ctx, scanStatus, err.Error()); updateErr != nil {
		s.logger.Warnf(ctx, "Failed to update scan status error: err=%+v", updateErr)
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
		return nil, fmt.Errorf("No gcp data, project_id=%d, gcp_id=%d, google_data_source_Id=%d", projectID, gcpID, googleDataSourceID)
	}
	return data.GcpDataSource, nil
}

func (s *SqsHandler) putFindings(ctx context.Context, projectID uint32, gcpProjectID string, f *cloudSploitFinding) error {
	score := s.cloudSploit.getScore(f)
	if score == 0.0 {
		// PutResource
		resp, err := s.findingClient.PutResource(ctx, &finding.PutResourceRequest{
			Resource: &finding.ResourceForUpsert{
				ResourceName: f.Resource,
				ProjectId:    projectID,
			},
		})
		if err != nil {
			s.logger.Errorf(ctx, "Failed to put reousrce project_id=%d, resource=%s, err=%+v", projectID, f.Resource, err)
			return err
		}
		if err := s.tagResource(ctx, common.TagGoogle, resp.Resource.ResourceId, projectID); err != nil {
			return err
		}
		if err := s.tagResource(ctx, common.TagGCP, resp.Resource.ResourceId, projectID); err != nil {
			return err
		}
		if err := s.tagResource(ctx, gcpProjectID, resp.Resource.ResourceId, projectID); err != nil {
			return err
		}
		if err := s.tagResource(ctx, strings.ToLower(f.Category), resp.Resource.ResourceId, projectID); err != nil {
			return err
		}
		return nil
	}

	buf, err := json.Marshal(f)
	if err != nil {
		s.logger.Errorf(ctx, "Failed to marshal user data, project_id=%d, resource=%s, err=%+v", projectID, f.Resource, err)
		return err
	}
	// PutFinding
	resp, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{
		Finding: &finding.FindingForUpsert{
			Description:      f.Description,
			DataSource:       message.GoogleCloudSploitDataSource,
			DataSourceId:     f.DataSourceID,
			ResourceName:     f.Resource,
			ProjectId:        projectID,
			OriginalScore:    score,
			OriginalMaxScore: 10.0,
			Data:             string(buf),
		},
	})
	if err != nil {
		s.logger.Errorf(ctx, "Failed to put finding project_id=%d, resource=%s, err=%+v", projectID, f.Resource, err)
		return err
	}
	// PutFindingTag
	if err := s.tagFinding(ctx, common.TagGoogle, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
		return err
	}
	if err := s.tagFinding(ctx, common.TagGCP, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
		return err
	}
	if err := s.tagFinding(ctx, common.TagCloudSploit, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
		return err
	}
	if err := s.tagFinding(ctx, strings.ToLower(f.Category), resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
		return err
	}
	if err := s.tagFinding(ctx, gcpProjectID, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
		return err
	}
	if err := s.tagFinding(ctx, f.Plugin, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
		return err
	}
	for _, t := range f.Tags {
		if err := s.tagFinding(ctx, t, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
			return err
		}
	}
	if err := s.putRecommend(ctx, resp.Finding.ProjectId, resp.Finding.FindingId, f); err != nil {
		return err
	}
	s.logger.Debugf(ctx, "Success to PutFinding, finding_id=%d", resp.Finding.FindingId)
	return nil
}

func (s *SqsHandler) tagFinding(ctx context.Context, tag string, findingID uint64, projectID uint32) error {
	if _, err := s.findingClient.TagFinding(ctx, &finding.TagFindingRequest{
		ProjectId: projectID,
		Tag: &finding.FindingTagForUpsert{
			FindingId: findingID,
			ProjectId: projectID,
			Tag:       tag,
		}}); err != nil {
		return fmt.Errorf("Failed to TagFinding, finding_id=%d, tag=%s, error=%+v", findingID, tag, err)
	}
	return nil
}

func (s *SqsHandler) tagResource(ctx context.Context, tag string, resourceID uint64, projectID uint32) error {
	if _, err := s.findingClient.TagResource(ctx, &finding.TagResourceRequest{
		ProjectId: projectID,
		Tag: &finding.ResourceTagForUpsert{
			ResourceId: resourceID,
			ProjectId:  projectID,
			Tag:        tag,
		}}); err != nil {
		return fmt.Errorf("Failed to TagResource, resource_id=%d, tag=%s, error=%+v", resourceID, tag, err)
	}
	return nil
}

func (s *SqsHandler) updateScanStatusError(ctx context.Context, putData *google.AttachGCPDataSourceRequest, statusDetail string) error {
	putData.GcpDataSource.Status = google.Status_ERROR
	putData.GcpDataSource.StatusDetail = statusDetail
	return s.updateScanStatus(ctx, putData)
}

func (s *SqsHandler) updateScanStatusSuccess(ctx context.Context, putData *google.AttachGCPDataSourceRequest, detail string) error {
	putData.GcpDataSource.Status = google.Status_OK
	putData.GcpDataSource.StatusDetail = detail
	return s.updateScanStatus(ctx, putData)
}

func (s *SqsHandler) updateScanStatus(ctx context.Context, putData *google.AttachGCPDataSourceRequest) error {
	resp, err := s.googleClient.AttachGCPDataSource(ctx, putData)
	if err != nil {
		return err
	}
	s.logger.Infof(ctx, "Success to update GCPDataSource status, response=%+v", resp)
	return nil
}

func (s *SqsHandler) analyzeAlert(ctx context.Context, projectID uint32) error {
	_, err := s.alertClient.AnalyzeAlert(ctx, &alert.AnalyzeAlertRequest{
		ProjectId: projectID,
	})
	return err
}

func (s *SqsHandler) putRecommend(ctx context.Context, projectID uint32, findingID uint64, f *cloudSploitFinding) error {
	categoryPlugin := fmt.Sprintf("%s/%s", f.Category, f.Plugin)
	r := s.cloudSploit.getRecommend(f)
	if r == nil || (r.Risk == nil && r.Recommendation == nil) {
		s.logger.Warnf(ctx, "Failed to get recommendation, Unknown plugin=%s", categoryPlugin)
		return nil
	}
	if _, err := s.findingClient.PutRecommend(ctx, &finding.PutRecommendRequest{
		ProjectId:      projectID,
		FindingId:      findingID,
		DataSource:     message.GoogleCloudSploitDataSource,
		Type:           categoryPlugin,
		Risk:           *r.Risk,
		Recommendation: *r.Recommendation,
	}); err != nil {
		return fmt.Errorf("Failed to TagFinding, finding_id=%d, plugin=%s, error=%+v", findingID, categoryPlugin, err)
	}
	s.logger.Debugf(ctx, "Success PutRecommend, finding_id=%d, reccomend=%+v", findingID, r)
	return nil
}
