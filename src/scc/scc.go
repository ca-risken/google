package main

import (
	"context"
	"fmt"
	"os"

	scc "cloud.google.com/go/securitycenter/apiv1"
	"github.com/gassara-kys/envconfig"
	"google.golang.org/api/option"
	sccpb "google.golang.org/genproto/googleapis/cloud/securitycenter/v1"
)

type sccServiceClient interface {
	listFinding(ctx context.Context, gcpOrganizationID, gcpProjectID string) *scc.ListFindingsResponse_ListFindingsResultIterator
}

type sccClient struct {
	client *scc.Client
}

type sccConfig struct {
	GoogleCredentialPath string `required:"true" split_words:"true" default:"/tmp/credential.json"`
}

func newSCCClient() sccServiceClient {
	var conf sccConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatalf("Could not read confg. err: %+v", err)
	}
	ctx := context.Background()
	c, err := scc.NewClient(ctx, option.WithCredentialsFile(conf.GoogleCredentialPath))
	if err != nil {
		appLogger.Fatalf("Failed to authenticate for Google API client: %+v", err)
	}
	// Remove credential file for Security
	if err := os.Remove(conf.GoogleCredentialPath); err != nil {
		appLogger.Fatalf("Failed to remove file: path=%s, err=%+v", conf.GoogleCredentialPath, err)
	}
	return &sccClient{client: c}
}

func (g *sccClient) listFinding(ctx context.Context, gcpOrganizationID, gcpProjectID string) *scc.ListFindingsResponse_ListFindingsResultIterator {
	// https://pkg.go.dev/google.golang.org/api/securitycenter/v1
	return g.client.ListFindings(ctx, &sccpb.ListFindingsRequest{
		// Parent: fmt.Sprintf("organizations/%s/sources/-", gcpOrganizationID),
		// Filter: fmt.Sprintf("source_properties.ProjectId = \"%s\"", gcpProjectID),
		Parent: fmt.Sprintf("projects/%s/sources/-", gcpProjectID),
	})
}

func scoreSCC(f *sccpb.Finding) float32 {
	if f.State != sccpb.Finding_ACTIVE {
		return 0.1
	}
	switch f.Severity {
	case sccpb.Finding_CRITICAL:
		return 0.9
	case sccpb.Finding_HIGH:
		return 0.6
	case sccpb.Finding_MEDIUM:
		return 0.3
	case sccpb.Finding_LOW:
		return 0.1
	}
	return 0.0
}
