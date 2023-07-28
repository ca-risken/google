package asset

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/asset/apiv1/assetpb"
	"cloud.google.com/go/iam"
	admin "cloud.google.com/go/iam/admin/apiv1/adminpb"
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
	"google.golang.org/api/cloudresourcemanager/v3"
)

type SqsHandler struct {
	findingClient finding.FindingServiceClient
	alertClient   alert.AlertServiceClient
	googleClient  google.GoogleServiceClient
	assetClient   assetServiceClient
	logger        logging.Logger
}

func NewSqsHandler(
	fc finding.FindingServiceClient,
	ac alert.AlertServiceClient,
	gc google.GoogleServiceClient,
	assetc assetServiceClient,
	l logging.Logger,
) *SqsHandler {
	return &SqsHandler{
		findingClient: fc,
		alertClient:   ac,
		googleClient:  gc,
		assetClient:   assetc,
		logger:        l,
	}
}

type assetFinding struct {
	Asset                  *assetpb.ResourceSearchResult `json:"asset"`
	IAMPolicy              *[]string                     `json:"iam_policy,omitempty"`
	HasServiceAccountKey   bool                          `json:"has_key,omitempty"`
	DisabledServiceAccount bool                          `json:"disabled_service_account,omitempty"`
	BucketPolicy           *iam.Policy                   `json:"bucket_policy,omitempty"`
}

func (s *SqsHandler) HandleMessage(ctx context.Context, sqsMsg *types.Message) error {
	msgBody := aws.ToString(sqsMsg.Body)
	s.logger.Infof(ctx, "got message: %s", msgBody)
	msg, err := message.ParseMessageGCP(msgBody)
	if err != nil {
		s.logger.Errorf(ctx, "invalid message: msg=%+v, err=%+v", sqsMsg, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	beforeScanAt := time.Now()
	requestID, err := s.logger.GenerateRequestID(fmt.Sprint(msg.ProjectID))
	if err != nil {
		s.logger.Warnf(ctx, "failed to generate requestID: err=%+v", err)
		requestID = fmt.Sprint(msg.ProjectID)
	}

	s.logger.Infof(ctx, "start google asset scan, RequestID=%s", requestID)
	s.logger.Infof(ctx, "start get GCP DataSource, RequestID=%s", requestID)
	gcp, err := s.getGCPDataSource(ctx, msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID)
	if err != nil {
		s.logger.Errorf(ctx, "failed to get gcp: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
			msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	s.logger.Infof(ctx, "end get GCP DataSource, RequestID=%s", requestID)
	scanStatus := common.InitScanStatus(gcp)

	iamPolicies, err := s.assetClient.getProjectIAMPolicy(ctx, gcp.GcpProjectId)
	if err != nil {
		s.updateStatusToError(ctx, scanStatus, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	serviceAccountMap, err := s.assetClient.getServiceAccountMap(ctx, gcp.GcpProjectId)
	if err != nil {
		s.updateStatusToError(ctx, scanStatus, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	// Get cloud asset
	s.logger.Infof(ctx, "start CloudAsset API, RequestID=%s", requestID)
	assetCounter := 0
	nextPageToken := ""
	it := s.assetClient.listAsset(ctx, gcp.GcpProjectId)
	for {
		result, err := s.assetClient.listAssetIterationCallWithRetry(ctx, it, nextPageToken)
		if err != nil {
			err = fmt.Errorf("failed to Cloud Asset API: project_id=%d, gcp_id=%d, google_data_source_id=%d, RequestID=%s, err=%w",
				msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, requestID, err)
			s.updateStatusToError(ctx, scanStatus, err)
			return mimosasqs.WrapNonRetryable(err)
		}
		if result == nil || len(result.resources) == 0 {
			break
		}

		assets := []*assetFinding{}
		for _, r := range result.resources {
			a, err := s.generateAssetFinding(ctx, gcp.GcpProjectId, r, iamPolicies, serviceAccountMap)
			if err != nil {
				err = fmt.Errorf("failed to generate asset findng: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%w",
					msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, err)
				s.updateStatusToError(ctx, scanStatus, err)
				return mimosasqs.WrapNonRetryable(err)
			}
			assets = append(assets, a)
		}

		// Put finding
		if len(assets) > 0 {
			if err := s.putFindings(ctx, msg.ProjectID, gcp.GcpProjectId, assets); err != nil {
				s.logger.Errorf(ctx, "failed to put findngs: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
					msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, err)
				s.updateStatusToError(ctx, scanStatus, err)
				return mimosasqs.WrapNonRetryable(err)
			}
		}
		assetCounter = assetCounter + len(assets)
		nextPageToken = result.token
		if result.token == "" {
			break
		}
	}
	s.logger.Infof(ctx, "got %d assets, RequestID=%s", assetCounter, requestID)
	s.logger.Infof(ctx, "end CloudAsset API, RequestID=%s", requestID)

	if err := s.updateScanStatusSuccess(ctx, scanStatus); err != nil {
		return mimosasqs.WrapNonRetryable(err)
	}

	// Clear score for inactive findings
	if _, err := s.findingClient.ClearScore(ctx, &finding.ClearScoreRequest{
		DataSource: message.GoogleAssetDataSource,
		ProjectId:  msg.ProjectID,
		Tag:        []string{gcp.GcpProjectId},
		BeforeAt:   beforeScanAt.Unix(),
	}); err != nil {
		s.logger.Errorf(ctx, "failed to clear finding score. GcpProjectID: %v, error: %v", gcp.GcpProjectId, err)
		s.updateStatusToError(ctx, scanStatus, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	s.logger.Infof(ctx, "end google asset scan, RequestID=%s", requestID)
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
		s.logger.Warnf(ctx, "failed to update scan status error: err=%+v", updateErr)
	}
}

func getShortName(name string) string {
	array := strings.Split(name, "/")
	return array[len(array)-1]
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

func (s *SqsHandler) putFindings(ctx context.Context, projectID uint32, gcpProjectID string, assets []*assetFinding) error {
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
			s.logger.Errorf(ctx, "failed to marshal user data, project_id=%d, assetName=%s, err=%+v", projectID, a.Asset.Name, err)
			return err
		}
		f := &finding.FindingBatchForUpsert{
			Finding: &finding.FindingForUpsert{
				Description:      getAssetDescription(a, score),
				DataSource:       message.GoogleAssetDataSource,
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
			s.logger.Warnf(ctx, "failed to get recommendation, Unknown type=%s", a.Asset.AssetType)
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
	s.logger.Infof(ctx, "putFindings(%d) succeeded", len(assets))
	return nil
}

func getAssetTags(assetType, assetName string) []string {
	tags := []string{common.GetServiceName(assetName)}
	if isUserServiceAccount(assetType, assetName) {
		tags = append(tags, common.TagServiceAccount)
	}
	return tags
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

const (
	userServiceAccountEmailPattern string = ".iam.gserviceaccount.com"

	// Basic roles: https://cloud.google.com/iam/docs/understanding-roles
	roleOwner  string = "roles/owner"
	roleEditor string = "roles/editor"
)

func (s *SqsHandler) generateAssetFinding(
	ctx context.Context,
	gcpProjectID string,
	r *assetpb.ResourceSearchResult,
	policy *cloudresourcemanager.Policy,
	serviceAccountMap map[string]*admin.ServiceAccount,
) (*assetFinding, error) {

	f := assetFinding{Asset: r}
	var err error
	// IAM
	if isUserServiceAccount(r.AssetType, r.Name) {
		email := getShortName(r.Name)
		f.HasServiceAccountKey, err = s.assetClient.hasUserManagedKeys(ctx, gcpProjectID, email)
		if err != nil {
			return nil, err
		}
		sa, ok := serviceAccountMap[generateServiceAccountKey(gcpProjectID, email)]
		if !ok {
			return nil, fmt.Errorf("not found service account, project=%s, email=%s", gcpProjectID, email)
		}
		f.DisabledServiceAccount = sa.Disabled
		f.IAMPolicy = getServiceAccountIAMPolicies(email, policy)
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

func getServiceAccountIAMPolicies(email string, policy *cloudresourcemanager.Policy) *[]string {
	policies := []string{}
	if policy == nil {
		return &policies
	}
	for _, b := range policy.Bindings {
		for _, m := range b.Members {
			if m == fmt.Sprintf("serviceAccount:%s", email) {
				policies = append(policies, b.Role)
				break
			}
		}
	}
	return &policies
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
	if f.IAMPolicy == nil || len(*f.IAMPolicy) == 0 {
		return 0.0
	}
	if !f.HasServiceAccountKey {
		return 0.1
	}
	if f.DisabledServiceAccount {
		return 0.1
	}
	for _, r := range *f.IAMPolicy {
		if r == roleOwner || r == roleEditor {
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
	assetPageSize = 1000
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

func getAssetDescription(a *assetFinding, score float32) string {
	assetType := ""
	if a.Asset.AssetType == assetTypeServiceAccount {
		assetType = "ServiceAccount"
		if score >= 0.8 {
			return fmt.Sprintf("Detected a privileged service-account that has owner(or editor) role. (name=%s)", a.Asset.DisplayName)
		}
	}
	if a.Asset.AssetType == assetTypeBucket {
		assetType = "Bucket"
		if score >= 0.7 {
			return fmt.Sprintf("Detected public bucket. (name=%s)", a.Asset.DisplayName)
		}
	}

	description := fmt.Sprintf("Detected GCP asset (name=%s)", a.Asset.DisplayName)
	if assetType != "" {
		description = fmt.Sprintf("Detected GCP asset (type=%s, name=%s)", assetType, a.Asset.DisplayName)
	}
	return description
}
