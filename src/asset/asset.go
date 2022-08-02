package main

import (
	"context"
	"fmt"
	"os"

	asset "cloud.google.com/go/asset/apiv1"
	"cloud.google.com/go/iam"
	admin "cloud.google.com/go/iam/admin/apiv1"
	"cloud.google.com/go/storage"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/option"
	assetpb "google.golang.org/genproto/googleapis/cloud/asset/v1"
	adminpb "google.golang.org/genproto/googleapis/iam/admin/v1"
)

type assetServiceClient interface {
	listAsset(ctx context.Context, gcpProjectID string) *asset.ResourceSearchResultIterator
	getProjectIAMPolicy(ctx context.Context, gcpProjectID string) (*cloudresourcemanager.Policy, error)
	hasUserManagedKeys(ctx context.Context, gcpProjectID, email string) (bool, error)
	getStorageBucketPolicy(ctx context.Context, bucketName string) (*iam.Policy, error)
}

type assetClient struct {
	project *cloudresourcemanager.Service
	asset   *asset.Client
	admin   *admin.IamClient
	gcs     *storage.Client
}

func newAssetClient(credentialPath string) (assetServiceClient, error) {
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
	}, nil
}

const (
	// Supported asset types: https://cloud.google.com/asset-inventory/docs/supported-asset-types
	assetTypeServiceAccount    string = "iam.googleapis.com/ServiceAccount"    // IAM
	assetTypeServiceAccountKey string = "iam.googleapis.com/ServiceAccountKey" // IAM
	assetTypeRole              string = "iam.googleapis.com/Role"              // IAM
	assetTypeBucket            string = "storage.googleapis.com/Bucket"        // Storage
)

func (a *assetClient) listAsset(ctx context.Context, gcpProjectID string) *asset.ResourceSearchResultIterator {
	return a.asset.SearchAllResources(ctx, &assetpb.SearchAllResourcesRequest{
		Scope: "projects/" + gcpProjectID,
		AssetTypes: []string{
			assetTypeServiceAccount,
			assetTypeServiceAccountKey,
			assetTypeRole,
			assetTypeBucket,
		},
	})
}

func (a *assetClient) getProjectIAMPolicy(ctx context.Context, gcpProjectID string) (*cloudresourcemanager.Policy, error) {
	// doc: https://cloud.google.com/resource-manager/reference/rest/v3/projects/getIamPolicy
	project := fmt.Sprintf("projects/%s", gcpProjectID)
	options := &cloudresourcemanager.GetIamPolicyRequest{}
	resp, err := a.project.Projects.GetIamPolicy(project, options).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (a *assetClient) hasUserManagedKeys(ctx context.Context, gcpProjectID, email string) (bool, error) {
	// doc: https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys/list
	name := fmt.Sprintf("projects/%s/serviceAccounts/%s", gcpProjectID, email)
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

func (a *assetClient) getStorageBucketPolicy(ctx context.Context, bucketName string) (*iam.Policy, error) {
	b := a.gcs.Bucket(bucketName)
	policy, err := b.IAM().Policy(ctx)
	if err != nil {
		return nil, fmt.Errorf("Failed to Bucket IAM Policy API, err=%+v", err)
	}
	appLogger.Debugf(ctx, "BucketPolicy: %+v", policy)
	return policy, nil
}
