package scc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	securitycenter "cloud.google.com/go/securitycenter/apiv1"
	sccpb "cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
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
	vulnmodel "github.com/ca-risken/vulnerability/pkg/model"
	vuln "github.com/ca-risken/vulnerability/pkg/sdk"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

type SqsHandler struct {
	findingClient           finding.FindingServiceClient
	alertClient             alert.AlertServiceClient
	googleClient            google.GoogleServiceClient
	sccClient               SCCServiceClient
	includeLowSeverity      bool
	reduceScoreFindingClass []string
	vulnClient              *vuln.Client
	logger                  logging.Logger
}

func NewSqsHandler(
	fc finding.FindingServiceClient,
	ac alert.AlertServiceClient,
	gc google.GoogleServiceClient,
	sccc SCCServiceClient,
	vc *vuln.Client,
	includeLowSeverity bool,
	reduceScoreFindingClass []string,
	l logging.Logger,
) *SqsHandler {
	return &SqsHandler{
		findingClient:           fc,
		alertClient:             ac,
		googleClient:            gc,
		sccClient:               sccc,
		vulnClient:              vc,
		includeLowSeverity:      includeLowSeverity,
		reduceScoreFindingClass: reduceScoreFindingClass,
		logger:                  l,
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

	beforeScanAt := time.Now()
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
	s.logger.Infof(ctx, "start SCC ListFinding API, RequestID=%s", requestID)
	tspan, tctx := tracer.StartSpanFromContext(ctx, "listFinding")
	it := s.sccClient.listFinding(tctx, gcp.GcpProjectId, s.includeLowSeverity)
	tspan.Finish()
	s.logger.Infof(ctx, "end SCC ListFinding API, RequestID=%s", requestID)

	s.logger.Infof(ctx, "start put findings, RequestID=%s", requestID)
	tspan, tctx2 := tracer.StartSpanFromContext(ctx, "putFindings")
	putCount, err := s.putFindings(tctx2, gcp, it)
	tspan.Finish(tracer.WithError(err))
	if err != nil {
		s.logger.Errorf(ctx, "Failed to put findings: project_id=%d, gcp_project_id=%d, err=%+v",
			gcp.ProjectId, gcp.GcpProjectId, err)
		s.updateStatusToError(ctx, scanStatus, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	s.logger.Infof(ctx, "end put findings(%d succeeded), RequestID=%s", *putCount, requestID)

	// Clear score for inactive findings
	if _, err := s.findingClient.ClearScore(ctx, &finding.ClearScoreRequest{
		DataSource: message.GoogleSCCDataSource,
		ProjectId:  msg.ProjectID,
		Tag:        []string{gcp.GcpProjectId},
		BeforeAt:   beforeScanAt.Unix(),
	}); err != nil {
		s.logger.Errorf(ctx, "failed to clear finding score. GcpProjectID: %v, error: %v", gcp.GcpProjectId, err)
		s.updateStatusToError(ctx, scanStatus, err)
		return mimosasqs.WrapNonRetryable(err)
	}

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

func (s *SqsHandler) putFindings(
	ctx context.Context,
	gcp *google.GCPDataSource,
	it *securitycenter.ListFindingsResponse_ListFindingsResultIterator,
) (*int, error) {
	nextPageToken := ""
	counter := 0
	for {
		result, err := s.sccClient.iterationFetchFindingsWithRetry(ctx, it, nextPageToken)
		if err != nil {
			return nil, fmt.Errorf("fetch error: err=%w", err)
		}
		if result == nil || len(result.findings) == 0 {
			break
		}

		findingBatchParam := []*finding.FindingBatchForUpsert{}
		for _, f := range result.findings {
			// TODO: ここでassetを取得する
			data, err := s.generateFindingData(ctx, gcp.ProjectId, gcp.GcpProjectId, f)
			if err != nil {
				return nil, fmt.Errorf("generate finding error: err=%w", err)
			}
			findingBatchParam = append(findingBatchParam, data)
		}
		if len(findingBatchParam) > 0 {
			err := grpc_client.PutFindingBatch(ctx, s.findingClient, gcp.ProjectId, findingBatchParam)
			if err != nil {
				return nil, fmt.Errorf("put finding error: err=%w", err)
			}
		}
		counter = counter + len(findingBatchParam)
		if result.token == "" {
			break
		}
		nextPageToken = result.token
	}
	return &counter, nil
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

type SccAsset struct {
	Type               string `json:"type,omitempty"`
	Service            string `json:"service,omitempty"`
	Location           string `json:"location,omitempty"`
	FullName           string `json:"full_name,omitempty"`
	DisplayName        string `json:"display_name,omitempty"`
	ParentDisplayName  string `json:"parent_display_name,omitempty"`
	ProjectDisplayName string `json:"project_display_name,omitempty"`
	Organization       string `json:"organization,omitempty"`
}

type SccFinding struct {
	Asset         *SccAsset                `json:"asset"`
	Finding       *sccpb.Finding           `json:"finding"`
	SccDetailURL  string                   `json:"scc_detail_url"`
	Vulnerability *vulnmodel.Vulnerability `json:"vulnerability,omitempty"`
}

func (s *SqsHandler) generateFindingData(ctx context.Context, projectID uint32, gcpProjectID string, findingResp *sccpb.ListFindingsResponse_ListFindingsResult) (*finding.FindingBatchForUpsert, error) {
	f := findingResp.GetFinding()
	resource := findingResp.GetResource()
	asset := &SccAsset{
		Type:               resource.GetType(),
		Service:            resource.GetService(),
		Location:           resource.GetLocation(),
		FullName:           resource.GetName(),
		DisplayName:        resource.GetDisplayName(),
		ParentDisplayName:  resource.GetParentDisplayName(),
		ProjectDisplayName: resource.GetProjectDisplayName(),
		Organization:       resource.GetOrganization(),
	}

	sccURL := generateSccURL(f.Name, gcpProjectID)
	cve := extractCVEID(f)
	vuln, err := s.GetVulnerability(ctx, cve)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerability, project_id=%d, cve_id=%s, err=%+v", projectID, cve, err)
	}
	data := &SccFinding{
		Asset:         asset,
		Finding:       f,
		SccDetailURL:  sccURL,
		Vulnerability: vuln,
	}
	buf, err := json.Marshal(data)
	if err != nil {
		s.logger.Errorf(ctx, "failed to marshal user data, project_id=%d, findingName=%s, err=%+v", projectID, f.Name, err)
		return nil, err
	}
	resourceShortName := extractShortResourceName(f.ResourceName)
	findingData := &finding.FindingBatchForUpsert{
		Finding: &finding.FindingForUpsert{
			Description:      generateSccDescrition(f.Category, cve, resourceShortName),
			DataSource:       message.GoogleSCCDataSource,
			DataSourceId:     f.Name,
			ResourceName:     f.ResourceName,
			ProjectId:        projectID,
			OriginalScore:    s.scoreSCC(f),
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
	if cve != "" {
		findingData.Tag = append(findingData.Tag, &finding.FindingTagForBatch{Tag: common.TagCVE})
		findingData.Tag = append(findingData.Tag, &finding.FindingTagForBatch{Tag: cve})
	}
	if resourceShortName != "" {
		findingData.Tag = append(findingData.Tag, &finding.FindingTagForBatch{Tag: resourceShortName})
	}

	riskDescription := f.Category
	if f.Description != "" {
		riskDescription += "\n" + f.Description
	} else if f.SourceProperties["Explanation"] != nil {
		riskDescription += "\n" + f.SourceProperties["Explanation"].GetStringValue()
	}
	if riskDescription != "" {
		findingData.Recommend = &finding.RecommendForBatch{
			Type: f.Name,
			Risk: riskDescription,
			Recommendation: fmt.Sprintf(`Please see the finding JSON data in 'recommendation' or 'next_steps' field.
And you can see the more information in the Security Command Center console.
- %s`, sccURL),
		}
	}
	return findingData, nil
}

func extractShortResourceName(resourceName string) string {
	array := strings.Split(resourceName, "/")
	if len(array) < 1 {
		return resourceName
	}
	return array[len(array)-1]
}

func extractCVEID(f *sccpb.Finding) string {
	if f.Vulnerability != nil && f.Vulnerability.Cve != nil {
		return f.Vulnerability.Cve.Id
	}
	return ""
}

func generateSccDescrition(category, cveID, resourceShortName string) string {
	desc := fmt.Sprintf("Detected a %s finding.", category)
	if cveID == "" && resourceShortName == "" {
		return desc
	}

	meta := "("
	if resourceShortName != "" {
		meta += fmt.Sprintf("Resource: %s", resourceShortName)
	}
	if cveID != "" {
		if meta != "(" {
			meta += ", "
		}
		meta += fmt.Sprintf("CVE: %s", cveID)
	}
	meta += ")"
	return desc + " " + meta
}

func generateSccURL(name, gcpProjectID string) string {
	encodedName := url.QueryEscape(name)
	return fmt.Sprintf("https://console.cloud.google.com/security/command-center/findingsv2;name=%s?project=%s", encodedName, gcpProjectID)
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
	s.logger.Infof(ctx, "success to update GCP DataSource status, response=%+v", resp)
	return nil
}

func (s *SqsHandler) analyzeAlert(ctx context.Context, projectID uint32) error {
	_, err := s.alertClient.AnalyzeAlert(ctx, &alert.AnalyzeAlertRequest{
		ProjectId: projectID,
	})
	return err
}
