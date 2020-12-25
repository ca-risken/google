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
	"google.golang.org/api/iterator"
	assetpb "google.golang.org/genproto/googleapis/cloud/asset/v1"
)

type sqsHandler struct {
	findingClient finding.FindingServiceClient
	alertClient   alert.AlertServiceClient
	googleClient  google.GoogleServiceClient
	gcpClient     gcpServiceClient
}

func newHandler() *sqsHandler {
	return &sqsHandler{
		findingClient: newFindingClient(),
		alertClient:   newAlertClient(),
		googleClient:  newGoogleClient(),
		gcpClient:     newGCPClient(),
	}
}

type assetFinding struct {
	Asset     *assetpb.ResourceSearchResult     `json:"asset"`
	IAMPolicy *assetpb.AnalyzeIamPolicyResponse `json:"iam_policy"`
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
	gcp, err := s.getGCP(ctx, message.ProjectID, message.GCPID)
	if err != nil {
		appLogger.Errorf("Failed to get gcp: project_id=%d, gcp_id=%d, err=%+v", message.ProjectID, message.GCPID, err)
		return err
	}
	scanStatus := s.initScanStatus(gcp)

	// Get cloud asset
	it := s.gcpClient.listAsset(ctx, gcp.GcpProjectId)
	for {
		resource, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			appLogger.Errorf("Failed to Coud Asset API: project_id=%d, gcp_id=%d, err=%+v", message.ProjectID, message.GCPID, err)
			return s.updateScanStatusError(ctx, scanStatus, err.Error())
		}
		f := assetFinding{Asset: resource}
		if isServiceAccount(resource.AssetType) {
			email := getShortNameFromResouceFullName(resource.Name)
			policy, err := s.gcpClient.analyzeServiceAccountPolicy(ctx, gcp.GcpProjectId, email)
			if err != nil {
				return s.updateScanStatusError(ctx, scanStatus, err.Error())
			}
			f.IAMPolicy = policy
		}
		appLogger.Debugf("Got: %+v", resource)
		// Put finding
		if err := s.putFindings(ctx, message.ProjectID, &f); err != nil {
			appLogger.Errorf("Failed to put findngs: project_id=%d, gcp_id=%d, err=%+v", message.ProjectID, message.GCPID, err)
			return s.updateScanStatusError(ctx, scanStatus, err.Error())
		}
	}

	if err := s.updateScanStatusSuccess(ctx, scanStatus); err != nil {
		return err
	}
	return s.analyzeAlert(ctx, message.ProjectID)
}

func (s *sqsHandler) getGCP(ctx context.Context, projectID, gcpID uint32) (*google.GCP, error) {
	data, err := s.googleClient.GetGCP(ctx, &google.GetGCPRequest{
		ProjectId: projectID,
		GcpId:     gcpID,
	})
	if err != nil {
		return nil, err
	}
	if data == nil || data.Gcp == nil {
		return nil, fmt.Errorf("No gcp data, project_id=%d, gcp_id=%d", projectID, gcpID)
	}
	return data.Gcp, nil
}

func (s *sqsHandler) initScanStatus(g *google.GCP) *google.PutGCPRequest {
	return &google.PutGCPRequest{
		ProjectId: g.ProjectId,
		Gcp: &google.GCPForUpsert{
			GcpId:              g.GcpId,
			GoogleDataSourceId: g.GoogleDataSourceId,
			Name:               g.Name,
			ProjectId:          g.ProjectId,
			GcpOrganizationId:  g.GcpOrganizationId,
			GcpProjectId:       g.GcpProjectId,
			ScanAt:             time.Now().Unix(),
			Status:             google.Status_UNKNOWN, // After scan, will be updated
			StatusDetail:       "",
		},
	}
}

func (s *sqsHandler) putFindings(ctx context.Context, projectID uint32, f *assetFinding) error {
	buf, err := json.Marshal(f)
	if err != nil {
		appLogger.Errorf("Failed to marshal user data, project_id=%d, assetName=%s, err=%+v", projectID, f.Asset.Name, err)
		return err
	}
	resp, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{
		Finding: &finding.FindingForUpsert{
			Description:      fmt.Sprintf("%s (GCP Cloud Asset)", f.Asset.DisplayName),
			DataSource:       common.AssetDataSource,
			DataSourceId:     f.Asset.Name,
			ResourceName:     f.Asset.DisplayName,
			ProjectId:        projectID,
			OriginalScore:    scoreAsset(f),
			OriginalMaxScore: 1.0,
			Data:             string(buf),
		},
	})
	if err != nil {
		appLogger.Errorf("Failed to put finding project_id=%d, assetName=%s, err=%+v", projectID, f.Asset.Name, err)
		return err
	}
	// finding-tag
	s.tagFinding(ctx, common.TagGCP, resp.Finding.FindingId, resp.Finding.ProjectId)
	s.tagFinding(ctx, common.TagAssetInventory, resp.Finding.FindingId, resp.Finding.ProjectId)
	if isServiceAccount(f.Asset.AssetType) {
		s.tagFinding(ctx, common.TagServiceAccount, resp.Finding.FindingId, resp.Finding.ProjectId)
	}
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

func (s *sqsHandler) updateScanStatusError(ctx context.Context, putData *google.PutGCPRequest, statusDetail string) error {
	putData.Gcp.Status = google.Status_ERROR
	statusDetail = cutString(statusDetail, 200)
	putData.Gcp.StatusDetail = statusDetail
	return s.updateScanStatus(ctx, putData)
}

func (s *sqsHandler) updateScanStatusSuccess(ctx context.Context, putData *google.PutGCPRequest) error {
	putData.Gcp.Status = google.Status_OK
	putData.Gcp.StatusDetail = ""
	return s.updateScanStatus(ctx, putData)
}

func (s *sqsHandler) updateScanStatus(ctx context.Context, putData *google.PutGCPRequest) error {
	resp, err := s.googleClient.PutGCP(ctx, putData)
	if err != nil {
		return err
	}
	appLogger.Infof("Success to update AWS status, response=%+v", resp)
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

func getShortNameFromResouceFullName(fullName string) string {
	// "name": "//iam.googleapis.com/projects/vulnasses/serviceAccounts/cloudsploit-scans@vulnasses.iam.gserviceaccount.com"
	array := strings.Split(fullName, "/")
	return array[len(array)-1]
}

const (
	// Supported asset types: https://cloud.google.com/asset-inventory/docs/supported-asset-types
	assetTypeServiceAccount string = "iam.googleapis.com/ServiceAccount"

	// Basic roles: https://cloud.google.com/iam/docs/understanding-roles
	roleOwner  string = "roles/owner"
	roleEditor string = "roles/editor"
)

func isServiceAccount(assetType string) bool {
	return assetType == assetTypeServiceAccount
}

func scoreAsset(f *assetFinding) float32 {
	if f == nil || f.Asset == nil {
		return 0.1
	}
	if isServiceAccount(f.Asset.AssetType) {
		if f.IAMPolicy == nil || f.IAMPolicy.MainAnalysis == nil || f.IAMPolicy.MainAnalysis.AnalysisResults == nil {
			return 0.1
		}
		for _, p := range f.IAMPolicy.MainAnalysis.AnalysisResults {
			if p.IamBinding == nil {
				continue
			}
			if p.IamBinding.Role == roleOwner || p.IamBinding.Role == roleEditor {
				return 0.8 // the serviceAccount has Admin role.
			}
		}
	}
	return 0.1
}
