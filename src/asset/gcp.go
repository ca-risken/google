package main

import (
	"context"
	"os"

	asset "cloud.google.com/go/asset/apiv1"
	"github.com/kelseyhightower/envconfig"
	"google.golang.org/api/option"
	assetpb "google.golang.org/genproto/googleapis/cloud/asset/v1"
)

type gcpServiceClient interface {
	listAsset(ctx context.Context, gcpProjectID string) *asset.ResourceSearchResultIterator
	analyzeServiceAccountPolicy(ctx context.Context, gcpProjectID, email string) (*assetpb.AnalyzeIamPolicyResponse, error)
}

type gcpClient struct {
	client *asset.Client
}

type gcpConfig struct {
	GoogleCredentialPath string `required:"true" split_words:"true"`
}

func newGCPClient() gcpServiceClient {
	var conf gcpConfig
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
	return &gcpClient{client: c}
}

func (g *gcpClient) listAsset(ctx context.Context, gcpProjectID string) *asset.ResourceSearchResultIterator {
	return g.client.SearchAllResources(ctx, &assetpb.SearchAllResourcesRequest{
		Scope: "projects/" + gcpProjectID,
	})
}

func (g *gcpClient) analyzeServiceAccountPolicy(ctx context.Context, gcpProjectID, email string) (*assetpb.AnalyzeIamPolicyResponse, error) {
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
