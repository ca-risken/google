package portscan

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/common/pkg/portscan"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	"github.com/ca-risken/core/proto/alert"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/datasource-api/pkg/message"
	"github.com/ca-risken/datasource-api/proto/google"
	"github.com/ca-risken/google/pkg/common"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

type SqsHandler struct {
	findingClient   finding.FindingServiceClient
	alertClient     alert.AlertServiceClient
	googleClient    google.GoogleServiceClient
	portscanClient  portscanServiceClient
	scanConcurrency int64
	logger          logging.Logger
}

func NewSqsHandler(
	fc finding.FindingServiceClient,
	ac alert.AlertServiceClient,
	gc google.GoogleServiceClient,
	pc portscanServiceClient,
	scanConcurrency int64,
	l logging.Logger,
) *SqsHandler {
	return &SqsHandler{
		findingClient:   fc,
		alertClient:     ac,
		googleClient:    gc,
		portscanClient:  pc,
		scanConcurrency: scanConcurrency,
		logger:          l,
	}
}

func (s *SqsHandler) HandleMessage(ctx context.Context, sqsMsg *types.Message) error {
	msgBody := aws.ToString(sqsMsg.Body)
	s.logger.Infof(ctx, "got message: %s", msgBody)
	msg, err := message.ParseMessageGCP(msgBody)
	if err != nil {
		s.logger.Errorf(ctx, "Invalid message: msg=%+v, err=%+v", msgBody, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	beforeScanAt := time.Now()
	requestID, err := s.logger.GenerateRequestID(fmt.Sprint(msg.ProjectID))
	if err != nil {
		s.logger.Warnf(ctx, "Failed to generate requestID: err=%+v", err)
		requestID = fmt.Sprint(msg.ProjectID)
	}

	s.logger.Infof(ctx, "start portscan, RequestID=%s", requestID)
	s.logger.Infof(ctx, "start getGCPDataSource, RequestID=%s", requestID)
	gcp, err := s.getGCPDataSource(ctx, msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID)
	if err != nil {
		s.logger.Errorf(ctx, "Failed to get gcp: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
			msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	s.logger.Infof(ctx, "end getGCPDataSource, RequestID=%s", requestID)
	scanStatus := common.InitScanStatus(gcp)

	// get target and scan target
	s.logger.Infof(ctx, "start exec scan, RequestID=%s", requestID)
	tspan, tctx := tracer.StartSpanFromContext(ctx, "scanTargets")
	err = s.scan(tctx, gcp.GcpProjectId, msg, s.scanConcurrency)
	tspan.Finish(tracer.WithError(err))
	if err != nil {
		s.updateStatusToError(ctx, scanStatus, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	s.logger.Infof(ctx, "end exec scan, RequestID=%s", requestID)

	// Clear finding score
	if _, err := s.findingClient.ClearScore(ctx, &finding.ClearScoreRequest{
		DataSource: message.GooglePortscanDataSource,
		ProjectId:  msg.ProjectID,
		Tag:        []string{gcp.GcpProjectId},
		BeforeAt:   beforeScanAt.Unix(),
	}); err != nil {
		s.logger.Errorf(ctx, "Failed to clear finding score. GCPProjectID: %v, error: %v", gcp.GcpProjectId, err)
		return err
	}

	s.logger.Infof(ctx, "start update scan status, RequestID=%s", requestID)
	if err := s.updateScanStatusSuccess(ctx, scanStatus); err != nil {
		return mimosasqs.WrapNonRetryable(err)
	}
	s.logger.Infof(ctx, "end update scan status, RequestID=%s", requestID)
	s.logger.Infof(ctx, "end portscan, RequestID=%s", requestID)
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

func (s *SqsHandler) scan(ctx context.Context, gcpProjectId string, msg *message.GCPQueueMessage, scanConcurrency int64) error {
	targets, relFirewallResourceMap, err := s.portscanClient.listTarget(ctx, gcpProjectId)
	if err != nil {
		return err
	}
	if targets == nil && relFirewallResourceMap == nil {
		s.logger.Infof(ctx, "No scan taget, project=%s", gcpProjectId)
		return nil // skip scan
	}
	targets, excludeList := s.portscanClient.excludeTarget(targets)
	eg, errGroupCtx := errgroup.WithContext(ctx)
	mutex := &sync.Mutex{}
	sem := semaphore.NewWeighted(scanConcurrency)
	var nmapResults []*portscan.NmapResult
	for _, t := range targets {
		if err := sem.Acquire(ctx, 1); err != nil {
			s.logger.Errorf(ctx, "failed to acquire semaphore: %v", err)
			return err
		}
		t := t
		eg.Go(func() error {
			defer sem.Release(1)
			select {
			case <-errGroupCtx.Done():
				s.logger.Debugf(ctx, "scan cancel. target: %v", t.Target)
				return nil
			default:
				results, err := s.portscanClient.scan(ctx, t)
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
		s.logger.Errorf(ctx, "failed to exec portscan: %v", err)
		return err
	}

	for _, result := range nmapResults {
		err := s.putNmapFindings(ctx, msg.ProjectID, gcpProjectId, result)
		if err != nil {
			s.logger.Errorf(ctx, "Failed to put Finding err: %v", err)
			return err
		}
	}
	if relFirewallResourceMap != nil {
		err := s.putRelFirewallResourceFindings(ctx, gcpProjectId, relFirewallResourceMap, msg)
		if err != nil {
			s.logger.Errorf(ctx, "Failed to put firewall resource Finding err: %v", err)
			return err
		}
	}
	err = s.putExcludeFindings(ctx, gcpProjectId, excludeList, msg)
	if err != nil {
		s.logger.Errorf(ctx, "Failed put exclude Finding err: %v", err)
		return err
	}
	return nil
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
		return nil, fmt.Errorf("No gcp data, project_id=%d, gcp_id=%d, google_data_source_id=%d", projectID, gcpID, googleDataSourceID)
	}
	return data.GcpDataSource, nil
}

func (s *SqsHandler) updateScanStatusError(ctx context.Context, putData *google.AttachGCPDataSourceRequest, statusDetail string) error {
	putData.GcpDataSource.Status = google.Status_ERROR
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
	s.logger.Infof(ctx, "Success to update GCP DataSource status, response=%+v", resp)
	return nil
}

func (s *SqsHandler) analyzeAlert(ctx context.Context, projectID uint32) error {
	_, err := s.alertClient.AnalyzeAlert(ctx, &alert.AnalyzeAlertRequest{
		ProjectId: projectID,
	})
	return err
}
