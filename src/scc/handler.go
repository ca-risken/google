package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-xray-sdk-go/xray"
	"github.com/ca-risken/common/pkg/logging"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	"github.com/ca-risken/core/proto/alert"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/google/pkg/common"
	"github.com/ca-risken/google/proto/google"
	"github.com/vikyd/zero"
	"google.golang.org/api/iterator"
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
		return s.finalize(ctx, nil, err)
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
		return s.finalize(ctx, &msg.ProjectID, err)
	}
	scanStatus := common.InitScanStatus(gcp)

	// Get security command center
	if gcp.GcpOrganizationId == "" || gcp.GcpProjectId == "" {
		err := fmt.Errorf("Required GcpOrganizationId and GcpProjectId parameters, GcpOrganizationId=%s, GcpProjectId=%s",
			gcp.GcpOrganizationId, gcp.GcpProjectId)
		appLogger.Errorf("Invalid parameters, project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
			msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, err)
		if updateErr := s.updateScanStatusError(ctx, scanStatus, err.Error()); updateErr != nil {
			appLogger.Warnf("Failed to update scan status error: err=%+v", updateErr)
		}
		return s.finalize(ctx, &msg.ProjectID, err)
	}
	appLogger.Infof("start SCC ListFinding API, RequestID=%s", requestID)
	xctx, segment := xray.BeginSubsegment(ctx, "listFinding")
	it := s.sccClient.listFinding(xctx, gcp.GcpOrganizationId, gcp.GcpProjectId)
	segment.Close(nil)
	appLogger.Infof("end SCC ListFinding API, RequestID=%s", requestID)

	findingCnt := 0
	for {
		f, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			appLogger.Errorf("Failed to Coud SCC API: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
				msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, err)
			if updateErr := s.updateScanStatusError(ctx, scanStatus, err.Error()); updateErr != nil {
				appLogger.Warnf("Failed to update scan status error: err=%+v", updateErr)
			}
			return s.finalize(ctx, &msg.ProjectID, err)
		}
		appLogger.Debugf("Got finding: %+v", f.Finding)
		// Put finding
		if err := s.putFindings(ctx, msg.ProjectID, gcp.GcpProjectId, f.Finding); err != nil {
			appLogger.Errorf("Failed to put findngs: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
				msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, err)
			if updateErr := s.updateScanStatusError(ctx, scanStatus, err.Error()); updateErr != nil {
				appLogger.Warnf("Failed to update scan status error: err=%+v", updateErr)
			}
			return s.finalize(ctx, &msg.ProjectID, err)
		}
		findingCnt++
	}
	appLogger.Infof("Got %d findings, RequestID=%s", findingCnt, requestID)

	if err := s.updateScanStatusSuccess(ctx, scanStatus); err != nil {
		return s.finalize(ctx, &msg.ProjectID, err)
	}
	appLogger.Infof("end SCC scan, RequestID=%s", requestID)
	if msg.ScanOnly {
		return s.finalize(ctx, &msg.ProjectID, nil)
	}
	if err := s.analyzeAlert(ctx, msg.ProjectID); err != nil {
		appLogger.Notifyf(logging.ErrorLevel, "Failed to analyzeAlert, project_id=%d, err=%+v", msg.ProjectID, err)
		return s.finalize(ctx, &msg.ProjectID, err)
	}
	return s.finalize(ctx, &msg.ProjectID, nil)
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
			ResourceName:     f.ResourceName,
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
	if err := s.tagFinding(ctx, common.TagGoogle, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
		return err
	}
	if err := s.tagFinding(ctx, common.TagGCP, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
		return err
	}
	if err := s.tagFinding(ctx, common.TagSCC, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
		return err
	}
	if err := s.tagFinding(ctx, gcpProjectID, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
		return err
	}
	if err := s.tagFinding(ctx, common.GetServiceName(f.ResourceName), resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
		return err
	}
	if f.Category != "" && f.SourceProperties["Explanation"] != nil && f.SourceProperties["Explanation"].GetStringValue() != "" {
		if err := s.putRecommend(ctx, resp.Finding.ProjectId, resp.Finding.FindingId, f.Category, f.SourceProperties["Explanation"].GetStringValue()); err != nil {
			return err
		}
	}
	appLogger.Infof("Success to PutFinding, finding_id=%d", resp.Finding.FindingId)
	return nil
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

func (s *sqsHandler) putRecommend(ctx context.Context, projectID uint32, findingID uint64, category, risk string) error {
	if _, err := s.findingClient.PutRecommend(ctx, &finding.PutRecommendRequest{
		ProjectId:      projectID,
		FindingId:      findingID,
		DataSource:     common.SCCDataSource,
		Type:           category,
		Risk:           risk,
		Recommendation: "Please see the finding JSON data in 'data.source_properties.Recommendation'",
	}); err != nil {
		return fmt.Errorf("Failed to TagFinding, finding_id=%d, category=%s, error=%+v", findingID, category, err)
	}
	appLogger.Debugf("Success PutRecommend, finding_id=%d, category=%s, risk=%s", findingID, category, risk)
	return nil
}

// finalize function summarizes the termination process
func (s *sqsHandler) finalize(ctx context.Context, projectID *uint32, err error) error {
	if err != nil && projectID == nil {
		return mimosasqs.WrapNonRetryable(err)
	}
	if err == nil {
		// Scan succeeded
		if putErr := s.putScanFinding(ctx, &scanFinding{
			ProjectID: *projectID,
			Status:    "OK",
		}); putErr != nil {
			appLogger.Errorf("Failed to putScanFinding(scan succeeded), err=%+v", putErr)
			return mimosasqs.WrapNonRetryable(putErr)
		}
		return nil
	}

	// Scan failed
	if putErr := s.putScanFinding(ctx, &scanFinding{
		ProjectID:    *projectID,
		Status:       "Error",
		ErrorMessage: err.Error(),
	}); putErr != nil {
		appLogger.Errorf("Failed to putScanFinding(scan failed), err=%+v", putErr)
		return mimosasqs.WrapNonRetryable(err)
	}
	return mimosasqs.WrapNonRetryable(err)
}

type scanFinding struct {
	ProjectID    uint32 `json:"project_id,omitempty"`
	Status       string `json:"status,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

func (s *sqsHandler) putScanFinding(ctx context.Context, sf *scanFinding) error {
	if sf == nil || zero.IsZeroVal(sf.ProjectID) {
		return nil // nop
	}
	score := float32(0.0)
	desc := fmt.Sprintf("Successfully scanned %s", common.SCCDataSource)
	if sf.ErrorMessage != "" {
		desc = fmt.Sprintf("Failed to scan %s", common.SCCDataSource)
		score = 0.8
	}

	buf, err := json.Marshal(sf)
	if err != nil {
		return err
	}
	// PutFinding
	resp, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{
		Finding: &finding.FindingForUpsert{
			Description:      desc,
			DataSource:       "RISKEN",
			DataSourceId:     fmt.Sprintf("%s-scan-status", common.SCCDataSource),
			ResourceName:     common.SCCDataSource,
			ProjectId:        sf.ProjectID,
			OriginalScore:    score,
			OriginalMaxScore: 1.0,
			Data:             string(buf),
		},
	})
	if err != nil {
		return err
	}
	if _, err := s.findingClient.PutRecommend(ctx, &finding.PutRecommendRequest{
		ProjectId:  sf.ProjectID,
		FindingId:  resp.Finding.FindingId,
		DataSource: "RISKEN",
		Type:       fmt.Sprintf("ScanError/%s", common.SCCDataSource),
		Risk:       fmt.Sprintf("Failed to scan %s, So you are not gathering the latest security threat information.", common.SCCDataSource),
		Recommendation: `Please review the following items and rescan,
		- Ensure the error message of the DataSource.
		- Ensure the access rights you set for the DataSource and the reachability of the network.
		- Refer to the documentation to make sure you have not omitted any of the steps you have set up.
		- https://docs.security-hub.jp/google/overview_gcp/
		- If this does not resolve the problem, or if you suspect that the problem is server-side, please contact the system administrators.`,
	}); err != nil {
		return fmt.Errorf("Failed to put scan finding recommned, finding_id=%d, error=%+v", resp.Finding.FindingId, err)
	}
	return nil
}
