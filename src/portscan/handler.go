package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-xray-sdk-go/xray"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/common/pkg/portscan"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	"github.com/ca-risken/core/proto/alert"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/google/pkg/common"
	"github.com/ca-risken/google/proto/google"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

type sqsHandler struct {
	findingClient   finding.FindingServiceClient
	alertClient     alert.AlertServiceClient
	googleClient    google.GoogleServiceClient
	portscanClient  portscanServiceClient
	scanConcurrency int64
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

	appLogger.Infof("start portscan, RequestID=%s", requestID)
	appLogger.Infof("start getGCPDataSource, RequestID=%s", requestID)
	gcp, err := s.getGCPDataSource(ctx, msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID)
	if err != nil {
		appLogger.Errorf("Failed to get gcp: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
			msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	appLogger.Infof("end getGCPDataSource, RequestID=%s", requestID)
	scanStatus := common.InitScanStatus(gcp)

	// get target and scan target
	appLogger.Infof("start exec scan, RequestID=%s", requestID)
	xctx, segment := xray.BeginSubsegment(ctx, "scanTargets")
	err = s.scan(xctx, gcp.GcpProjectId, msg, s.scanConcurrency)
	segment.Close(err)
	if err != nil {
		return s.handleErrorWithUpdateStatus(ctx, scanStatus, err)
	}
	appLogger.Infof("end exec scan, RequestID=%s", requestID)

	appLogger.Infof("start update scan status, RequestID=%s", requestID)
	if err := s.updateScanStatusSuccess(ctx, scanStatus); err != nil {
		return mimosasqs.WrapNonRetryable(err)
	}
	appLogger.Infof("end update scan status, RequestID=%s", requestID)
	appLogger.Infof("end portscan, RequestID=%s", requestID)
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

func (s *sqsHandler) scan(ctx context.Context, gcpProjectId string, message *common.GCPQueueMessage, scanConcurrency int64) error {
	targets, relFirewallResourceMap, err := s.portscanClient.listTarget(ctx, gcpProjectId)
	if err != nil {
		return err
	}
	targets, excludeList := s.portscanClient.excludeTarget(targets)
	eg, errGroupCtx := errgroup.WithContext(ctx)
	mutex := &sync.Mutex{}
	sem := semaphore.NewWeighted(scanConcurrency)
	var nmapResults []*portscan.NmapResult
	for _, t := range targets {
		if err := sem.Acquire(ctx, 1); err != nil {
			appLogger.Errorf("failed to acquire semaphore: %v", err)
			return err
		}
		t := t
		eg.Go(func() error {
			defer sem.Release(1)
			select {
			case <-errGroupCtx.Done():
				appLogger.Debugf("scan cancel. target: %v", t.Target)
				return nil
			default:
				results, err := scan(t)
				if err != nil {
					return err
				}
				mutex.Lock()
				nmapResults = append(nmapResults, results...)
				mutex.Unlock()
				return nil
			}
		})
	}
	if err := eg.Wait(); err != nil {
		appLogger.Errorf("failed to exec portscan: %v", err)
		return err
	}

	// Clear finding score
	if _, err := s.findingClient.ClearScore(ctx, &finding.ClearScoreRequest{
		DataSource: common.PortscanDataSource,
		ProjectId:  message.ProjectID,
		Tag:        []string{gcpProjectId},
	}); err != nil {
		appLogger.Errorf("Failed to clear finding score. GCPProjectID: %v, error: %v", gcpProjectId, err)
		return err
	}
	for _, result := range nmapResults {
		err := s.putNmapFindings(ctx, message.ProjectID, gcpProjectId, result)
		if err != nil {
			appLogger.Errorf("Failed put Finding err: %v", err)
		}
	}
	if relFirewallResourceMap != nil {
		err := s.putRelFirewallResourceFindings(ctx, gcpProjectId, relFirewallResourceMap, message)
		if err != nil {
			appLogger.Errorf("Failed put Finding err: %v", err)
		}
	}
	err = s.putExcludeFindings(ctx, gcpProjectId, excludeList, message)
	if err != nil {
		appLogger.Errorf("Failed put exclude Finding err: %v", err)
	}
	return nil
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
