package asset

import (
	"context"
	"fmt"
	"os"
	"time"

	asset "cloud.google.com/go/asset/apiv1"
	"cloud.google.com/go/asset/apiv1/assetpb"
	"cloud.google.com/go/iam"
	admin "cloud.google.com/go/iam/admin/apiv1"
	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	"cloud.google.com/go/storage"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/cenkalti/backoff/v4"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/option"
)

type assetServiceClient interface {
	listAsset(ctx context.Context, gcpProjectID string) *asset.ResourceSearchResultIterator
	listAssetIterationCallWithRetry(ctx context.Context, it *asset.ResourceSearchResultIterator, pageToken string) (*assetIterationResult, error)
	getProjectIAMPolicy(ctx context.Context, gcpProjectID string) (*cloudresourcemanager.Policy, error)
	hasUserManagedKeys(ctx context.Context, gcpProjectID, email string) (bool, error)
	getStorageBucketPolicy(ctx context.Context, bucketName string) (*iam.Policy, error)
	getStoragePublicAccessPrevention(ctx context.Context, bucketName string) (*storage.PublicAccessPrevention, error)
	getServiceAccountMap(ctx context.Context, gcpProjectID string) (map[string]*adminpb.ServiceAccount, error)
}

type assetClient struct {
	project *cloudresourcemanager.Service
	asset   *asset.Client
	admin   *admin.IamClient
	gcs     *storage.Client
	logger  logging.Logger
	retryer backoff.BackOff
}

func NewAssetClient(credentialPath string, l logging.Logger) (assetServiceClient, error) {
	ctx := context.Background()
	pj, err := cloudresourcemanager.NewService(ctx, option.WithCredentialsFile(credentialPath))
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate for CloudResourceManager API client: %w", err)
	}
	as, err := asset.NewClient(ctx, option.WithCredentialsFile(credentialPath))
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate for Google Asset API client: %w", err)
	}
	ad, err := admin.NewIamClient(ctx, option.WithCredentialsFile(credentialPath))
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate for Google IAM Admin API client: %w", err)
	}
	st, err := storage.NewClient(ctx, option.WithCredentialsFile(credentialPath))
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate for Google Cloud Storage client: %w", err)
	}
	// Remove credential file for Security
	if err := os.Remove(credentialPath); err != nil {
		return nil, fmt.Errorf("failed to remove file: path=%s, err=%w", credentialPath, err)
	}
	return &assetClient{
		project: pj,
		asset:   as,
		admin:   ad,
		gcs:     st,
		logger:  l,
		retryer: backoff.WithMaxRetries(backoff.NewExponentialBackOff(), 10),
	}, nil
}

const (
	// Supported asset types: https://cloud.google.com/asset-inventory/docs/supported-asset-types
	assetTypeServiceAccount    string = "iam.googleapis.com/ServiceAccount"    // IAM
	assetTypeServiceAccountKey string = "iam.googleapis.com/ServiceAccountKey" // IAM
	assetTypeRole              string = "iam.googleapis.com/Role"              // IAM
	assetTypeBucket            string = "storage.googleapis.com/Bucket"        // Storage
)

func generateProjectKey(gcpProjectID string) string {
	return fmt.Sprintf("projects/%s", gcpProjectID)
}

func generateServiceAccountKey(gcpProjectID, email string) string {
	return fmt.Sprintf("projects/%s/serviceAccounts/%s", gcpProjectID, email)
}

func (a *assetClient) listAsset(ctx context.Context, gcpProjectID string) *asset.ResourceSearchResultIterator {
	return a.asset.SearchAllResources(ctx, &assetpb.SearchAllResourcesRequest{
		Scope: generateProjectKey(gcpProjectID),
		AssetTypes: []string{
			assetTypeServiceAccount,
			assetTypeServiceAccountKey,
			assetTypeRole,
			assetTypeBucket,
		},
	})
}

type assetIterationResult struct {
	resources []*assetpb.ResourceSearchResult
	token     string
}

func (a *assetClient) listAssetIterationCallWithRetry(ctx context.Context, it *asset.ResourceSearchResultIterator, pageToken string) (*assetIterationResult, error) {
	operation := func() (*assetIterationResult, error) {
		return a.listAssetIterationCall(it, pageToken)
	}
	return backoff.RetryNotifyWithData(operation, a.retryer, a.newRetryLogger(ctx, "listAssetIterationCall"))
}

func (a *assetClient) listAssetIterationCall(it *asset.ResourceSearchResultIterator, pageToken string) (*assetIterationResult, error) {
	resources, token, err := it.InternalFetch(assetPageSize, pageToken)
	if err != nil {
		return nil, err
	}
	return &assetIterationResult{
		resources: resources,
		token:     token,
	}, nil
}

func (a *assetClient) getProjectIAMPolicy(ctx context.Context, gcpProjectID string) (*cloudresourcemanager.Policy, error) {
	// doc: https://cloud.google.com/resource-manager/reference/rest/v3/projects/getIamPolicy
	project := generateProjectKey(gcpProjectID)
	options := &cloudresourcemanager.GetIamPolicyRequest{}
	resp, err := a.project.Projects.GetIamPolicy(project, options).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (a *assetClient) hasUserManagedKeys(ctx context.Context, gcpProjectID, email string) (bool, error) {
	// doc: https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys/list
	name := generateServiceAccountKey(gcpProjectID, email)
	keys, err := a.admin.ListServiceAccountKeys(ctx, &adminpb.ListServiceAccountKeysRequest{
		Name: name,
		KeyTypes: []adminpb.ListServiceAccountKeysRequest_KeyType{
			adminpb.ListServiceAccountKeysRequest_USER_MANAGED,
		},
	})
	if err != nil {
		return false, err
	}
	if keys != nil && len(keys.Keys) > 0 {
		return true, nil
	}
	return false, nil
}

func (a *assetClient) getServiceAccountMap(ctx context.Context, gcpProjectID string) (map[string]*adminpb.ServiceAccount, error) {
	results := map[string]*adminpb.ServiceAccount{}
	// doc: https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/list
	it := a.admin.ListServiceAccounts(ctx, &adminpb.ListServiceAccountsRequest{
		Name: generateProjectKey(gcpProjectID),
	})
	nextPageToken := ""
	for {
		list, token, err := it.InternalFetch(100, nextPageToken)
		if err != nil {
			return nil, err
		}
		for _, sa := range list {
			results[generateServiceAccountKey(gcpProjectID, sa.Email)] = sa
		}
		if token == "" {
			break
		}
		nextPageToken = token
	}
	return results, nil
}

func (a *assetClient) getStorageBucketPolicy(ctx context.Context, bucketName string) (*iam.Policy, error) {
	b := a.gcs.Bucket(bucketName)
	policy, err := b.IAM().Policy(ctx)
	if err != nil {
		return nil, fmt.Errorf("Failed to Bucket IAM Policy API, err=%+v", err)
	}
	return policy, nil
}

func (a *assetClient) getStoragePublicAccessPrevention(ctx context.Context, bucketName string) (*storage.PublicAccessPrevention, error) {
	b := a.gcs.Bucket(bucketName)
	attrs, err := b.Attrs(ctx)
	if err != nil {
		return nil, fmt.Errorf("Failed to Bucket Attributes API, err=%+v", err)
	}
	return &attrs.PublicAccessPrevention, nil
}

func (a *assetClient) newRetryLogger(ctx context.Context, funcName string) func(error, time.Duration) {
	return func(err error, t time.Duration) {
		a.logger.Warnf(ctx, "[RetryLogger] %s error: duration=%+v, err=%+v", funcName, t, err)
	}
}
