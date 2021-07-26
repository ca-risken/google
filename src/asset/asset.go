package main

import (
	"context"
	"fmt"
	"os"

	asset "cloud.google.com/go/asset/apiv1"
	admin "cloud.google.com/go/iam/admin/apiv1"
	"github.com/aws/aws-xray-sdk-go/xray"
	"github.com/kelseyhightower/envconfig"
	"google.golang.org/api/option"
	assetpb "google.golang.org/genproto/googleapis/cloud/asset/v1"
	adminpb "google.golang.org/genproto/googleapis/iam/admin/v1"
)

type assetServiceClient interface {
	listAsset(ctx context.Context, gcpProjectID string) *asset.ResourceSearchResultIterator
	analyzeServiceAccountPolicy(ctx context.Context, gcpProjectID, email string) (*assetpb.AnalyzeIamPolicyResponse, error)
	hasUserManagedKeys(ctx context.Context, gcpProjectID, email string) (bool, error)
}

type assetClient struct {
	asset *asset.Client
	admin *admin.IamClient
}

type assetConfig struct {
	GoogleCredentialPath string `required:"true" split_words:"true"`
}

func newAssetClient() assetServiceClient {
	var conf assetConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatalf("Could not read confg. err: %+v", err)
	}
	ctx := context.Background()
	as, err := asset.NewClient(ctx, option.WithCredentialsFile(conf.GoogleCredentialPath))
	if err != nil {
		appLogger.Fatalf("Failed to authenticate for Google Asset API client: %+v", err)
	}
	ad, err := admin.NewIamClient(ctx, option.WithCredentialsFile(conf.GoogleCredentialPath))
	if err != nil {
		appLogger.Fatalf("Failed to authenticate for Google IAM Admin API client: %+v", err)
	}

	// Remove credential file for Security
	if err := os.Remove(conf.GoogleCredentialPath); err != nil {
		appLogger.Fatalf("Failed to remove file: path=%s, err=%+v", conf.GoogleCredentialPath, err)
	}
	return &assetClient{
		asset: as,
		admin: ad,
	}
}

const (
	// Supported asset types: https://cloud.google.com/asset-inventory/docs/supported-asset-types
	assetTypeServiceAccount    string = "iam.googleapis.com/ServiceAccount"    // IAM
	assetTypeServiceAccountKey string = "iam.googleapis.com/ServiceAccountKey" // IAM
	assetTypeRole              string = "iam.googleapis.com/Role"              // IAM
	assetTypeBucket            string = "storage.googleapis.com/Bucket"        // Storage
)

func (a *assetClient) listAsset(ctx context.Context, gcpProjectID string) *asset.ResourceSearchResultIterator {
	_, segment := xray.BeginSubsegment(ctx, "asset.SearchAllResources")
	ret := a.asset.SearchAllResources(ctx, &assetpb.SearchAllResourcesRequest{
		Scope: "projects/" + gcpProjectID,
		AssetTypes: []string{
			assetTypeServiceAccount,
			assetTypeServiceAccountKey,
			assetTypeRole,
			assetTypeBucket,
		},
	})
	segment.Close(nil)
	return ret
}

func (a *assetClient) analyzeServiceAccountPolicy(ctx context.Context, gcpProjectID, email string) (*assetpb.AnalyzeIamPolicyResponse, error) {
	_, segment := xray.BeginSubsegment(ctx, "asset.AnalyzeIamPolicy")
	resp, err := a.asset.AnalyzeIamPolicy(ctx, &assetpb.AnalyzeIamPolicyRequest{
		AnalysisQuery: &assetpb.IamPolicyAnalysisQuery{
			Scope: "projects/" + gcpProjectID,
			IdentitySelector: &assetpb.IamPolicyAnalysisQuery_IdentitySelector{
				Identity: "serviceAccount:" + email,
			},
		},
	})
	segment.Close(err)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (a *assetClient) hasUserManagedKeys(ctx context.Context, gcpProjectID, email string) (bool, error) {
	// doc: https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys/list
	name := fmt.Sprintf("projects/%s/serviceAccounts/%s", gcpProjectID, email)
	// keys, err := a.admin.Projects.ServiceAccounts.Keys.List(name).Context(ctx).Do(&iampb.)
	_, segment := xray.BeginSubsegment(ctx, "admin.ListServiceAccountKeys")
	keys, err := a.admin.ListServiceAccountKeys(ctx, &adminpb.ListServiceAccountKeysRequest{
		Name: name,
		KeyTypes: []adminpb.ListServiceAccountKeysRequest_KeyType{
			adminpb.ListServiceAccountKeysRequest_USER_MANAGED,
		},
	})
	segment.Close(err)
	if err != nil {
		return false, err
	}
	if keys != nil && len(keys.Keys) > 0 {
		return true, nil
	}
	return false, nil
}
