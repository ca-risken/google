package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	asset "cloud.google.com/go/asset/apiv1"
	"cloud.google.com/go/iam"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/ca-risken/common/pkg/grpc_client"
	"github.com/ca-risken/common/pkg/logging"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	"github.com/ca-risken/core/proto/alert"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/google/pkg/common"
	"github.com/ca-risken/google/proto/google"
	assetpb "google.golang.org/genproto/googleapis/cloud/asset/v1"
)

type sqsHandler struct {
	findingClient finding.FindingServiceClient
	alertClient   alert.AlertServiceClient
	googleClient  google.GoogleServiceClient
	assetClient   assetServiceClient

	waitMilliSecPerRequest int
	assetAPIRetryNum       int
	assetAPIRetryWaitSec   int
}

type assetFinding struct {
	Asset                *assetpb.ResourceSearchResult     `json:"asset"`
	IAMPolicy            *assetpb.AnalyzeIamPolicyResponse `json:"iam_policy,omitempty"`
	HasServiceAccountKey bool                              `json:"has_key,omitempty"`
	BucketPolicy         *iam.Policy                       `json:"bucket_policy,omitempty"`
}

func (s *sqsHandler) HandleMessage(ctx context.Context, sqsMsg *types.Message) error {
	msgBody := aws.ToString(sqsMsg.Body)
	appLogger.Infof(ctx, "got message: %s", msgBody)
	msg, err := common.ParseMessage(msgBody)
	if err != nil {
		appLogger.Errorf(ctx, "invalid message: msg=%+v, err=%+v", sqsMsg, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	requestID, err := appLogger.GenerateRequestID(fmt.Sprint(msg.ProjectID))
	if err != nil {
		appLogger.Warnf(ctx, "failed to generate requestID: err=%+v", err)
		requestID = fmt.Sprint(msg.ProjectID)
	}

	appLogger.Infof(ctx, "start google asset scan, RequestID=%s", requestID)
	appLogger.Infof(ctx, "start get GCP DataSource, RequestID=%s", requestID)
	gcp, err := s.getGCPDataSource(ctx, msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID)
	if err != nil {
		appLogger.Errorf(ctx, "failed to get gcp: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
			msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	appLogger.Infof(ctx, "end get GCP DataSource, RequestID=%s", requestID)
	scanStatus := common.InitScanStatus(gcp)

	// Clear finding score
	if _, err := s.findingClient.ClearScore(ctx, &finding.ClearScoreRequest{
		DataSource: common.AssetDataSource,
		ProjectId:  msg.ProjectID,
		Tag:        []string{gcp.GcpProjectId},
	}); err != nil {
		appLogger.Errorf(ctx, "failed to clear finding score. GcpProjectID: %v, error: %v", gcp.GcpProjectId, err)
		return s.handleErrorWithUpdateStatus(ctx, scanStatus, err)
	}

	// Get cloud asset
	appLogger.Infof(ctx, "start CloudAsset API, RequestID=%s", requestID)
	assetCounter := 0
	nextPageToken := ""
	it := s.assetClient.listAsset(ctx, gcp.GcpProjectId)
	for {
		resources, token, err := s.listAssetIterationCallWithRetry(ctx, it, nextPageToken)
		if err != nil {
			return s.handleErrorWithUpdateStatus(ctx, scanStatus,
				fmt.Errorf("failed to Cloud Asset API: project_id=%d, gcp_id=%d, google_data_source_id=%d, RequestID=%s, err=%+v",
					msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, requestID, err))
		}

		assets := []*assetFinding{}
		for _, r := range resources {
			a, err := s.generateAssetFinding(ctx, gcp.GcpProjectId, r)
			if err != nil {
				return s.handleErrorWithUpdateStatus(ctx, scanStatus,
					fmt.Errorf("failed to generate asset findng: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
						msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, err))
			}
			assets = append(assets, a)
		}

		// Put finding
		if len(assets) > 0 {
			if err := s.putFindings(ctx, msg.ProjectID, gcp.GcpProjectId, assets); err != nil {
				appLogger.Errorf(ctx, "failed to put findngs: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
					msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, err)
				return s.handleErrorWithUpdateStatus(ctx, scanStatus, err)
			}
		}
		assetCounter = assetCounter + len(assets)
		nextPageToken = token
		if token == "" {
			break
		}

		// Control the number of API requests so that they are not exceeded.
		time.Sleep(time.Duration(s.waitMilliSecPerRequest) * time.Millisecond)
	}
	appLogger.Infof(ctx, "got %d assets, RequestID=%s", assetCounter, requestID)
	appLogger.Infof(ctx, "end CloudAsset API, RequestID=%s", requestID)

	if err := s.updateScanStatusSuccess(ctx, scanStatus); err != nil {
		return mimosasqs.WrapNonRetryable(err)
	}
	appLogger.Infof(ctx, "end google asset scan, RequestID=%s", requestID)
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
		appLogger.Warnf(ctx, "failed to update scan status error: err=%+v", updateErr)
	}
	return mimosasqs.WrapNonRetryable(err)
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
		return nil, fmt.Errorf("no gcp data, project_id=%d, gcp_id=%d, google_data_source_id=%d", projectID, gcpID, googleDataSourceID)
	}
	return data.GcpDataSource, nil
}

func (s *sqsHandler) putFindings(ctx context.Context, projectID uint32, gcpProjectID string, assets []*assetFinding) error {
	resources := []*finding.ResourceBatchForUpsert{}
	findings := []*finding.FindingBatchForUpsert{}
	for _, a := range assets {
		score := scoreAsset(a)
		if score == 0.0 {
			// Resource
			r := &finding.ResourceBatchForUpsert{
				Resource: &finding.ResourceForUpsert{
					ResourceName: a.Asset.Name,
					ProjectId:    projectID,
				},
			}
			tags := []*finding.ResourceTagForBatch{
				{Tag: common.TagGoogle},
				{Tag: common.TagGCP},
				{Tag: gcpProjectID},
			}
			for _, t := range getAssetTags(a.Asset.AssetType, a.Asset.Name) {
				tags = append(tags, &finding.ResourceTagForBatch{Tag: t})
			}
			r.Tag = tags
			resources = append(resources, r)
			continue
		}

		// Finding
		buf, err := json.Marshal(a)
		if err != nil {
			appLogger.Errorf(ctx, "failed to marshal user data, project_id=%d, assetName=%s, err=%+v", projectID, a.Asset.Name, err)
			return err
		}
		f := &finding.FindingBatchForUpsert{
			Finding: &finding.FindingForUpsert{
				Description:      fmt.Sprintf("GCP Cloud Asset: %s", a.Asset.DisplayName),
				DataSource:       common.AssetDataSource,
				DataSourceId:     a.Asset.Name,
				ResourceName:     a.Asset.Name,
				ProjectId:        projectID,
				OriginalScore:    score,
				OriginalMaxScore: 1.0,
				Data:             string(buf),
			},
		}
		tags := []*finding.FindingTagForBatch{
			{Tag: common.TagGoogle},
			{Tag: common.TagGCP},
			{Tag: common.TagAssetInventory},
			{Tag: gcpProjectID},
		}
		for _, t := range getAssetTags(a.Asset.AssetType, a.Asset.Name) {
			tags = append(tags, &finding.FindingTagForBatch{Tag: t})
		}
		f.Tag = tags

		r := getRecommend(a.Asset.AssetType)
		if r.Risk == "" && r.Recommendation == "" {
			appLogger.Warnf(ctx, "failed to get recommendation, Unknown type=%s", a.Asset.AssetType)
		} else {
			f.Recommend = &finding.RecommendForBatch{
				Type:           a.Asset.AssetType,
				Risk:           r.Risk,
				Recommendation: r.Recommendation,
			}
		}
		findings = append(findings, f)
	}
	// put
	if err := grpc_client.PutResourceBatch(ctx, s.findingClient, projectID, resources); err != nil {
		return err
	}
	if err := grpc_client.PutFindingBatch(ctx, s.findingClient, projectID, findings); err != nil {
		return err
	}
	appLogger.Infof(ctx, "putFindings(%d) succeeded", len(assets))
	return nil
}

func getAssetTags(assetType, assetName string) []string {
	tags := []string{common.GetServiceName(assetName)}
	if isUserServiceAccount(assetType, assetName) {
		tags = append(tags, common.TagServiceAccount)
	}
	return tags
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
	appLogger.Infof(ctx, "success to update GCP DataSource status, response=%+v", resp)
	return nil
}

func (s *sqsHandler) analyzeAlert(ctx context.Context, projectID uint32) error {
	_, err := s.alertClient.AnalyzeAlert(ctx, &alert.AnalyzeAlertRequest{
		ProjectId: projectID,
	})
	return err
}

const (
	userServiceAccountEmailPattern string = ".iam.gserviceaccount.com"

	// Basic roles: https://cloud.google.com/iam/docs/understanding-roles
	roleOwner  string = "roles/owner"
	roleEditor string = "roles/editor"
)

func (s *sqsHandler) generateAssetFinding(ctx context.Context, gcpProjectID string, r *assetpb.ResourceSearchResult) (*assetFinding, error) {
	f := assetFinding{Asset: r}
	var err error
	// IAM
	if isUserServiceAccount(r.AssetType, r.Name) {
		email := getShortName(r.Name)
		f.HasServiceAccountKey, err = s.assetClient.hasUserManagedKeys(ctx, gcpProjectID, email)
		if err != nil {
			return nil, err
		}
		f.IAMPolicy, err = s.assetClient.analyzeServiceAccountPolicy(ctx, gcpProjectID, email)
		if err != nil {
			return nil, err
		}
	}

	// Storage
	if r.AssetType == assetTypeBucket {
		f.BucketPolicy, err = s.assetClient.getStorageBucketPolicy(ctx, r.DisplayName)
		if err != nil {
			return nil, err
		}
	}
	return &f, nil
}

func isUserServiceAccount(assetType, name string) bool {
	return assetType == assetTypeServiceAccount && strings.HasSuffix(name, userServiceAccountEmailPattern)
}

func scoreAsset(f *assetFinding) float32 {
	if f == nil || f.Asset == nil {
		return 0.0
	}
	// IAM
	if isUserServiceAccount(f.Asset.AssetType, f.Asset.Name) {
		return scoreAssetForIAM(f)
	}
	// Storage
	if f.Asset.AssetType == assetTypeBucket {
		return scoreAssetForStorage(f)
	}
	return 0.0
}

func scoreAssetForIAM(f *assetFinding) float32 {
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

func scoreAssetForStorage(f *assetFinding) float32 {
	if f.BucketPolicy == nil || f.BucketPolicy.InternalProto == nil {
		return 0.0
	}
	var score float32 = 0.1
	for _, b := range f.BucketPolicy.InternalProto.Bindings {
		public := allowedPubliclyAccess(b.Members)
		writable := writableRole(b.Role)
		if public && writable {
			score = 1.0 // `writable` means both READ and WRITE.
			break
		}
		if public {
			score = 0.7 // read only access
		}
	}
	return score
}

const (
	assetPageSize = 200
	// https://cloud.google.com/storage/docs/access-control/lists#scopes
	allUsers              string = "allUsers"
	allAuthenticatedUsers string = "allAuthenticatedUsers"
)

func allowedPubliclyAccess(members []string) bool {
	for _, m := range members {
		if m == allUsers || m == allAuthenticatedUsers {
			return true
		}
	}
	return false
}

func writableRole(role string) bool {
	// https://cloud.google.com/storage/docs/access-control/iam-roles
	// Not supported custom roles.
	if strings.HasSuffix(strings.ToLower(role), "reader") || strings.HasSuffix(strings.ToLower(role), "viewer") {
		return false
	}
	return true
}

func (s *sqsHandler) listAssetIterationCallWithRetry(ctx context.Context, it *asset.ResourceSearchResultIterator, pageToken string) (resource []*assetpb.ResourceSearchResult, nextPageToken string, err error) {
	for i := 0; i <= s.assetAPIRetryNum; i++ {
		if i > 0 {
			time.Sleep(time.Duration(s.assetAPIRetryWaitSec+i) * time.Second)
		}

		// API Call
		resources, token, err := it.InternalFetch(assetPageSize, pageToken)
		if err != nil {
			// Retry
			// https://cloud.google.com/apis/design/errors#retrying_errors
			// > For 429 RESOURCE_EXHAUSTED errors, the client may retry at the higher level with minimum 30s delay.
			// > Such retries are only useful for long running background jobs.
			if i < s.assetAPIRetryNum {
				appLogger.Warnf(ctx, "failed to Cloud Asset API, But retry call API after %d seconds..., retry=%d/%d, API Result=%+v, err=%+v",
					s.assetAPIRetryWaitSec+i, i+1, s.assetAPIRetryNum, resource, err)
			}
			continue
		}
		return resources, token, nil
	}
	return nil, "", fmt.Errorf("Failed to call Asset API, err=%+v", err)
}
