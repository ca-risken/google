package asset

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"cloud.google.com/go/asset/apiv1/assetpb"
	"cloud.google.com/go/storage"
	"github.com/ca-risken/common/pkg/dlp"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/datasource-api/pkg/message"
)

const (
	// https://cloud.google.com/storage/docs/access-control/lists#scopes
	allUsers              string = "allUsers"
	allAuthenticatedUsers string = "allAuthenticatedUsers"
)

func (s *SqsHandler) enrichBucketFinding(
	ctx context.Context,
	projectID uint32,
	gcpProjectID string,
	resource *assetpb.ResourceSearchResult,
	fullScan bool,
	f *assetFinding,
) error {
	if resource == nil {
		return fmt.Errorf("resource is nil")
	}

	var err error
	f.BucketPolicy, err = s.assetClient.getStorageBucketPolicy(ctx, resource.DisplayName)
	if err != nil {
		return err
	}

	f.BucketPublicAccessPrevention, err = s.assetClient.getStoragePublicAccessPrevention(ctx, resource.DisplayName)
	if err != nil {
		return fmt.Errorf("failed to get storage public access prevention, project=%s, bucket=%s, err=%w", gcpProjectID, resource.DisplayName, err)
	}

	if !isBucketPublic(f) {
		return nil
	}

	// Public bucket
	dlpResult, dlpErr := s.runBucketDLPScan(ctx, projectID, resource, fullScan)
	if dlpErr != nil {
		s.logger.Warnf(ctx, "failed to run DLP scan, project=%s, bucket=%s, err=%+v", gcpProjectID, resource.DisplayName, dlpErr)
	}
	if dlpResult != nil {
		f.DlpScan = dlpResult
	}
	return nil
}

func (s *SqsHandler) runBucketDLPScan(ctx context.Context, projectID uint32, resource *assetpb.ResourceSearchResult, fullScan bool) (*dlp.ScanResult, error) {
	if resource == nil {
		return nil, fmt.Errorf("resource is nil")
	}
	prevResult, err := s.getPreviousBucketDLPFinding(ctx, projectID, resource.Name)
	if err != nil {
		s.logger.Warnf(ctx, "failed to load previous DLP finding, project_id=%d, resource=%s, err=%+v", projectID, resource.Name, err)
		prevResult = nil
	}

	result, scanErr := s.assetClient.dlpScanBucket(ctx, resource.DisplayName, prevResult, fullScan)
	if scanErr != nil {
		return prevResult, scanErr
	}
	if result == nil {
		return prevResult, nil
	}
	return result, nil
}

func (s *SqsHandler) getPreviousBucketDLPFinding(ctx context.Context, projectID uint32, resourceName string) (*dlp.ScanResult, error) {
	listReq := &finding.ListFindingRequest{
		ProjectId:    projectID,
		DataSource:   []string{message.GoogleAssetDataSource},
		ResourceName: []string{resourceName},
		Limit:        1,
	}
	listResp, err := s.findingClient.ListFinding(ctx, listReq)
	if err != nil {
		return nil, fmt.Errorf("failed to list findings: %w", err)
	}
	if listResp == nil || len(listResp.FindingId) == 0 {
		return nil, nil
	}

	findingID := listResp.FindingId[0]
	getResp, err := s.findingClient.GetFinding(ctx, &finding.GetFindingRequest{
		ProjectId: projectID,
		FindingId: findingID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get finding detail, finding_id=%d: %w", findingID, err)
	}
	if getResp == nil || getResp.Finding == nil {
		return nil, fmt.Errorf("finding response is empty, finding_id=%d", findingID)
	}
	if !hasDLPScanData(getResp.Finding.Data) {
		return nil, nil
	}
	return parseDLPScanData(getResp.Finding.Data)
}

func hasDLPScanData(data string) bool {
	var parsed map[string]any
	if err := json.Unmarshal([]byte(data), &parsed); err != nil {
		return false
	}
	_, ok := parsed["dlp_scan"]
	return ok
}

func parseDLPScanData(data string) (*dlp.ScanResult, error) {
	var parsed map[string]any
	if err := json.Unmarshal([]byte(data), &parsed); err != nil {
		return nil, fmt.Errorf("failed to unmarshal finding data: %w", err)
	}

	raw, ok := parsed["dlp_scan"]
	if !ok {
		return nil, fmt.Errorf("dlp_scan field not found in finding data")
	}

	bytes, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal dlp_scan data: %w", err)
	}

	var result dlp.ScanResult
	if err := json.Unmarshal(bytes, &result); err != nil {
		return nil, fmt.Errorf("failed to parse dlp_scan data: %w", err)
	}
	return &result, nil
}

func isBucketPublic(f *assetFinding) bool {
	public, _ := bucketPublicAccessState(f)
	return public
}

func scoreAssetForStorage(f *assetFinding) float32 {
	if f.BucketPolicy == nil || f.BucketPolicy.InternalProto == nil {
		return 0.0
	}
	public, writable := bucketPublicAccessState(f)
	if !public {
		return 0.1
	}
	if writable {
		return 1.0
	}
	return 0.7
}

func bucketPublicAccessState(f *assetFinding) (public bool, writable bool) {
	if f == nil || f.BucketPolicy == nil || f.BucketPolicy.InternalProto == nil {
		return false, false
	}
	for _, b := range f.BucketPolicy.InternalProto.Bindings {
		if !allowedPubliclyAccess(b.Members, f.BucketPublicAccessPrevention) {
			continue
		}
		public = true
		if writableRole(b.Role) {
			writable = true
			break
		}
	}
	return
}

func allowedPubliclyAccess(members []string, publicAccessPrevention *storage.PublicAccessPrevention) bool {
	if publicAccessPrevention != nil {
		switch *publicAccessPrevention {
		case storage.PublicAccessPreventionEnforced:
			return false // Bucket level setting
		}
	}
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
