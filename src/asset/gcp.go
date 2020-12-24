package main

import (
	"context"

	"github.com/CyberAgent/mimosa-google/proto/google"
	"github.com/kelseyhightower/envconfig"
)

type gcpServiceClient interface {
	listAsset(ctx context.Context, config *google.GCP) (*[]assetFinding, error)
}

type gcpClient struct {
	googleCredentialPath     string
	googleServiceAccountJSON string
}

type gcpConfig struct {
	GoogleCredentialPath     string `required:"true" split_words:"true"`
	GoogleServiceAccountJSON string `required:"true" split_words:"true"`
}

func newGCPClient() gcpServiceClient {
	var conf gcpConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatalf("Could not read githubConfig. err: %+v", err)
	}
	return &gcpClient{
		googleCredentialPath:     conf.GoogleCredentialPath,
		googleServiceAccountJSON: conf.GoogleServiceAccountJSON,
	}
}

type assetFinding struct {
	Project              string `json:"project,omitempty`
	Name                 string `json:"name,omitempty`
	DisplayName          string `json:"displayName,omitempty`
	Description          string `json:"description,omitempty`
	AssetType            string `json:"assetType,omitempty`
	AdditionalAttributes struct {
		Email    string `json:"email,omitempty`
		uniqueID string `json:"uniqueId,omitempty`
	} `json:"additionalAttributes,omitempty`
}

func (g *gcpClient) listAsset(ctx context.Context, config *google.GCP) (*[]assetFinding, error) {
	var findings []assetFinding
	return &findings, nil
}
