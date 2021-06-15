package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

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
	assetClient   assetServiceClient
}

func newHandler() *sqsHandler {
	return &sqsHandler{
		findingClient: newFindingClient(),
		alertClient:   newAlertClient(),
		googleClient:  newGoogleClient(),
		assetClient:   newAssetClient(),
	}
}

type assetFinding struct {
	Asset                *assetpb.ResourceSearchResult     `json:"asset"`
	IAMPolicy            *assetpb.AnalyzeIamPolicyResponse `json:"iam_policy"`
	HasServiceAccountKey bool                              `json:"has_key"`
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
	gcp, err := s.getGCPDataSource(ctx, message.ProjectID, message.GCPID, message.GoogleDataSourceID)
	if err != nil {
		appLogger.Errorf("Failed to get gcp: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
			message.ProjectID, message.GCPID, message.GoogleDataSourceID, err)
		return err
	}
	scanStatus := common.InitScanStatus(gcp)

	// Get cloud asset
	it := s.assetClient.listAsset(ctx, gcp.GcpProjectId)
	for {
		resource, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			appLogger.Errorf("Failed to Coud Asset API: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
				message.ProjectID, message.GCPID, message.GoogleDataSourceID, err)
			return s.updateScanStatusError(ctx, scanStatus, err.Error())
		}
		f := assetFinding{Asset: resource}
		if isUserServiceAccount(resource.AssetType, resource.Name) {
			email := getShortName(resource.Name)
			hasKey, err := s.assetClient.hasUserManagedKeys(ctx, gcp.GcpProjectId, email)
			if err != nil {
				return s.updateScanStatusError(ctx, scanStatus, err.Error())
			}
			f.HasServiceAccountKey = hasKey
			policy, err := s.assetClient.analyzeServiceAccountPolicy(ctx, gcp.GcpProjectId, email)
			if err != nil {
				return s.updateScanStatusError(ctx, scanStatus, err.Error())
			}
			f.IAMPolicy = policy
		}
		appLogger.Debugf("Got: %+v", resource)
		// Put finding
		if err := s.putFindings(ctx, message.ProjectID, gcp.GcpProjectId, &f); err != nil {
			appLogger.Errorf("Failed to put findngs: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
				message.ProjectID, message.GCPID, message.GoogleDataSourceID, err)
			return s.updateScanStatusError(ctx, scanStatus, err.Error())
		}
	}

	if err := s.updateScanStatusSuccess(ctx, scanStatus); err != nil {
		return err
	}
	return s.analyzeAlert(ctx, message.ProjectID)
}

func getShortName(name string) string {
	array := strings.Split(name, "/")
	return array[len(array)-1]
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

func (s *sqsHandler) putFindings(ctx context.Context, projectID uint32, gcpProjectID string, f *assetFinding) error {
	score := scoreAsset(f)
	if score == 0.0 {
		// PutResource
		resp, err := s.findingClient.PutResource(ctx, &finding.PutResourceRequest{
			Resource: &finding.ResourceForUpsert{
				ResourceName: common.GetShortResourceName(gcpProjectID, f.Asset.Name),
				ProjectId:    projectID,
			},
		})
		if err != nil {
			appLogger.Errorf("Failed to put finding project_id=%d, assetName=%s, err=%+v", projectID, f.Asset.Name, err)
			return err
		}
		appLogger.Infof("Success to PutResource, finding_id=%d", resp.Resource.ResourceId)
		return nil
	}

	buf, err := json.Marshal(f)
	if err != nil {
		appLogger.Errorf("Failed to marshal user data, project_id=%d, assetName=%s, err=%+v", projectID, f.Asset.Name, err)
		return err
	}
	// PutFinding
	resp, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{
		Finding: &finding.FindingForUpsert{
			Description:      fmt.Sprintf("GCP Cloud Asset: %s", f.Asset.DisplayName),
			DataSource:       common.AssetDataSource,
			DataSourceId:     f.Asset.Name,
			ResourceName:     common.GetShortResourceName(gcpProjectID, f.Asset.Name),
			ProjectId:        projectID,
			OriginalScore:    score,
			OriginalMaxScore: 1.0,
			Data:             string(buf),
		},
	})
	if err != nil {
		appLogger.Errorf("Failed to put finding project_id=%d, assetName=%s, err=%+v", projectID, f.Asset.Name, err)
		return err
	}
	// PutFindingTag
	s.tagFinding(ctx, common.TagGCP, resp.Finding.FindingId, resp.Finding.ProjectId)
	s.tagFinding(ctx, common.TagAssetInventory, resp.Finding.FindingId, resp.Finding.ProjectId)
	s.tagFinding(ctx, gcpProjectID, resp.Finding.FindingId, resp.Finding.ProjectId)
	if isUserServiceAccount(f.Asset.AssetType, f.Asset.Name) {
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

const (
	// Supported asset types: https://cloud.google.com/asset-inventory/docs/supported-asset-types
	assetTypeServiceAccount        string = "iam.googleapis.com/ServiceAccount"
	userServiceAccountEmailPattern string = ".iam.gserviceaccount.com"

	// Basic roles: https://cloud.google.com/iam/docs/understanding-roles
	roleOwner  string = "roles/owner"
	roleEditor string = "roles/editor"
)

func isUserServiceAccount(assetType, name string) bool {
	return assetType == assetTypeServiceAccount && strings.HasSuffix(name, userServiceAccountEmailPattern)
}

func scoreAsset(f *assetFinding) float32 {
	if f == nil || f.Asset == nil {
		return 0.0
	}
	if isUserServiceAccount(f.Asset.AssetType, f.Asset.Name) {
		if f.IAMPolicy == nil || f.IAMPolicy.MainAnalysis == nil || f.IAMPolicy.MainAnalysis.AnalysisResults == nil {
			return 0.0
		}
		if !f.HasServiceAccountKey {
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
		return 0.1
	}
	return 0.0
}
