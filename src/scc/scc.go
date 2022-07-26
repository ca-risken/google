package main

import (
	"context"
	"fmt"
	"os"

	scc "cloud.google.com/go/securitycenter/apiv1"
	"google.golang.org/api/option"
	sccpb "google.golang.org/genproto/googleapis/cloud/securitycenter/v1"
)

type sccServiceClient interface {
	listFinding(ctx context.Context, gcpOrganizationID, gcpProjectID string) *scc.ListFindingsResponse_ListFindingsResultIterator
}

type sccClient struct {
	client *scc.Client
}

func newSCCClient(ctx context.Context, credentialPath string) (sccServiceClient, error) {
	c, err := scc.NewClient(ctx, option.WithCredentialsFile(credentialPath))
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate for Google API client: %w", err)
	}
	// Remove credential file for Security
	if err := os.Remove(credentialPath); err != nil {
		return nil, fmt.Errorf("failed to remove file: path=%s, err=%w", credentialPath, err)
	}
	return &sccClient{client: c}, nil
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
