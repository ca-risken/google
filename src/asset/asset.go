package main

import (
	"context"
	"os"

	asset "cloud.google.com/go/asset/apiv1"
	"github.com/kelseyhightower/envconfig"
	"google.golang.org/api/option"
	assetpb "google.golang.org/genproto/googleapis/cloud/asset/v1"
)

type assetServiceClient interface {
	listAsset(ctx context.Context, gcpProjectID string) *asset.ResourceSearchResultIterator
	analyzeServiceAccountPolicy(ctx context.Context, gcpProjectID, email string) (*assetpb.AnalyzeIamPolicyResponse, error)
}

type assetClient struct {
	client *asset.Client
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
	c, err := asset.NewClient(ctx, option.WithCredentialsFile(conf.GoogleCredentialPath))
	if err != nil {
		appLogger.Fatalf("Failed to authenticate for Google API client: %+v", err)
	}
	// Remove credential file for Security
	if err := os.Remove(conf.GoogleCredentialPath); err != nil {
		appLogger.Fatalf("Failed to remove file: path=%s, err=%+v", conf.GoogleCredentialPath, err)
	}
	return &assetClient{client: c}
}

func (g *assetClient) listAsset(ctx context.Context, gcpProjectID string) *asset.ResourceSearchResultIterator {
	return g.client.SearchAllResources(ctx, &assetpb.SearchAllResourcesRequest{
		Scope: "projects/" + gcpProjectID,
	})
}

func (g *assetClient) analyzeServiceAccountPolicy(ctx context.Context, gcpProjectID, email string) (*assetpb.AnalyzeIamPolicyResponse, error) {
	resp, err := g.client.AnalyzeIamPolicy(ctx, &assetpb.AnalyzeIamPolicyRequest{
		AnalysisQuery: &assetpb.IamPolicyAnalysisQuery{
			Scope: "projects/" + gcpProjectID,
			IdentitySelector: &assetpb.IamPolicyAnalysisQuery_IdentitySelector{
				Identity: "serviceAccount:" + email,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}
