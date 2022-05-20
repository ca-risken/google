package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/ca-risken/common/pkg/logging"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	"github.com/ca-risken/core/proto/alert"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/google/pkg/common"
	"github.com/ca-risken/google/proto/google"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

type sqsHandler struct {
	findingClient finding.FindingServiceClient
	alertClient   alert.AlertServiceClient
	googleClient  google.GoogleServiceClient
	cloudSploit   cloudSploitServiceClient
}

func (s *sqsHandler) HandleMessage(ctx context.Context, sqsMsg *types.Message) error {
	msgBody := aws.ToString(sqsMsg.Body)
	appLogger.Infof(ctx, "got message: %s", msgBody)
	msg, err := common.ParseMessage(msgBody)
	if err != nil {
		appLogger.Errorf(ctx, "Invalid message: msg=%+v, err=%+v", sqsMsg, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	requestID, err := appLogger.GenerateRequestID(fmt.Sprint(msg.ProjectID))
	if err != nil {
		appLogger.Warnf(ctx, "Failed to generate requestID: err=%+v", err)
		requestID = fmt.Sprint(msg.ProjectID)
	}

	appLogger.Infof(ctx, "start CloudSploit scan, RequestID=%s", requestID)
	appLogger.Infof(ctx, "start getGCPDataSource, RequestID=%s", requestID)
	gcp, err := s.getGCPDataSource(ctx, msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID)
	if err != nil {
		appLogger.Errorf(ctx, "Failed to get gcp: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
			msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	appLogger.Infof(ctx, "end getGCPDataSource, RequestID=%s", requestID)
	scanStatus := common.InitScanStatus(gcp)

	// Get cloud sploit
	appLogger.Infof(ctx, "start Run cloudsploit, RequestID=%s", requestID)
	tspan, tctx := tracer.StartSpanFromContext(ctx, "runCloudSploit")
	result, err := s.cloudSploit.run(tctx, gcp.GcpProjectId)
	tspan.Finish(tracer.WithError(err))
	appLogger.Infof(ctx, "end Run cloudsploit, RequestID=%s", requestID)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to run CloudSploit scan: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
			msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, err)
		appLogger.Error(ctx, errMsg)
		return s.handleErrorWithUpdateStatus(ctx, scanStatus, errors.New(errMsg))
	}
	appLogger.Infof(ctx, "start put finding, RequestID=%s", requestID)

	// Clear finding score
	if _, err := s.findingClient.ClearScore(ctx, &finding.ClearScoreRequest{
		DataSource: common.CloudSploitDataSource,
		ProjectId:  msg.ProjectID,
		Tag:        []string{gcp.GcpProjectId},
	}); err != nil {
		appLogger.Errorf(ctx, "Failed to clear finding score. GcpProjectID: %v, error: %v", gcp.GcpProjectId, err)
		return s.handleErrorWithUpdateStatus(ctx, scanStatus, err)
	}

	for _, f := range *result {
		// Put finding
		if err := s.putFindings(ctx, msg.ProjectID, gcp.GcpProjectId, &f); err != nil {
			errMsg := fmt.Sprintf("Failed to put findngs: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
				msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, err)
			appLogger.Error(ctx, errMsg)
			return s.handleErrorWithUpdateStatus(ctx, scanStatus, err)
		}
	}
	appLogger.Infof(ctx, "end put finding, RequestID=%s", requestID)

	appLogger.Infof(ctx, "start update scan status, RequestID=%s", requestID)
	if err := s.updateScanStatusSuccess(ctx, scanStatus); err != nil {
		return mimosasqs.WrapNonRetryable(err)
	}
	appLogger.Infof(ctx, "end update scan status, RequestID=%s", requestID)
	appLogger.Infof(ctx, "end CloudSploit scan, RequestID=%s", requestID)
	if msg.ScanOnly {
		return nil
	}
	if err := s.analyzeAlert(ctx, msg.ProjectID); err != nil {
		appLogger.Notifyf(ctx, logging.ErrorLevel, "Failed to analyzeAlert, project_id=%d, err=%+v", msg.ProjectID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	return nil
}

func (s *sqsHandler) handleErrorWithUpdateStatus(ctx context.Context, scanStatus *google.AttachGCPDataSourceRequest, err error) error {
	if updateErr := s.updateScanStatusError(ctx, scanStatus, err.Error()); updateErr != nil {
		appLogger.Warnf(ctx, "Failed to update scan status error: err=%+v", updateErr)
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
		return nil, fmt.Errorf("No gcp data, project_id=%d, gcp_id=%d, google_data_source_Id=%d", projectID, gcpID, googleDataSourceID)
	}
	return data.GcpDataSource, nil
}

func (s *sqsHandler) putFindings(ctx context.Context, projectID uint32, gcpProjectID string, f *cloudSploitFinding) error {
	score := f.getScore()
	if score == 0.0 {
		// PutResource
		resp, err := s.findingClient.PutResource(ctx, &finding.PutResourceRequest{
			Resource: &finding.ResourceForUpsert{
				ResourceName: getFormatResourceName(gcpProjectID, f.Category, f.Resource),
				ProjectId:    projectID,
			},
		})
		if err != nil {
			appLogger.Errorf(ctx, "Failed to put reousrce project_id=%d, resource=%s, err=%+v", projectID, f.Resource, err)
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

	f.setTags()
	buf, err := json.Marshal(f)
	if err != nil {
		appLogger.Errorf(ctx, "Failed to marshal user data, project_id=%d, resource=%s, err=%+v", projectID, f.Resource, err)
		return err
	}
	// PutFinding
	resp, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{
		Finding: &finding.FindingForUpsert{
			Description:      f.Description,
			DataSource:       common.CloudSploitDataSource,
			DataSourceId:     f.DataSourceID,
			ResourceName:     getFormatResourceName(gcpProjectID, f.Category, f.Resource),
			ProjectId:        projectID,
			OriginalScore:    score,
			OriginalMaxScore: 1.0,
			Data:             string(buf),
		},
	})
	if err != nil {
		appLogger.Errorf(ctx, "Failed to put finding project_id=%d, resource=%s, err=%+v", projectID, f.Resource, err)
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
	appLogger.Debugf(ctx, "Success to PutFinding, finding_id=%d", resp.Finding.FindingId)
	return nil
}

func getFormatResourceName(project, service, resource string) string {
	return fmt.Sprintf("%s/%s/%s", project, service, getShortName(resource))
}

func getShortName(name string) string {
	array := strings.Split(name, "/")
	return array[len(array)-1]
}

func (s *sqsHandler) tagFinding(ctx context.Context, tag string, findingID uint64, projectID uint32) error {
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

func (s *sqsHandler) tagResource(ctx context.Context, tag string, resourceID uint64, projectID uint32) error {
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
	appLogger.Infof(ctx, "Success to update GCPDataSource status, response=%+v", resp)
	return nil
}

func (s *sqsHandler) analyzeAlert(ctx context.Context, projectID uint32) error {
	_, err := s.alertClient.AnalyzeAlert(ctx, &alert.AnalyzeAlertRequest{
		ProjectId: projectID,
	})
	return err
}

func (s *sqsHandler) putRecommend(ctx context.Context, projectID uint32, findingID uint64, f *cloudSploitFinding) error {
	categoryPlugin := fmt.Sprintf("%s/%s", f.Category, f.Plugin)
	r := f.getRecommend()
	if r.Risk == "" && r.Recommendation == "" {
		appLogger.Warnf(ctx, "Failed to get recommendation, Unknown plugin=%s", categoryPlugin)
		return nil
	}
	if _, err := s.findingClient.PutRecommend(ctx, &finding.PutRecommendRequest{
		ProjectId:      projectID,
		FindingId:      findingID,
		DataSource:     common.CloudSploitDataSource,
		Type:           categoryPlugin,
		Risk:           r.Risk,
		Recommendation: r.Recommendation,
	}); err != nil {
		return fmt.Errorf("Failed to TagFinding, finding_id=%d, plugin=%s, error=%+v", findingID, categoryPlugin, err)
	}
	appLogger.Debugf(ctx, "Success PutRecommend, finding_id=%d, reccomend=%+v", findingID, r)
	return nil
}
