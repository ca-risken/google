package scc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	sccv2 "cloud.google.com/go/securitycenter/apiv2"
	sccv2pb "cloud.google.com/go/securitycenter/apiv2/securitycenterpb"
	"github.com/ca-risken/common/pkg/grpc_client"
	riskenstr "github.com/ca-risken/common/pkg/strings"
	triage "github.com/ca-risken/core/pkg/server/finding"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/datasource-api/pkg/message"
	"github.com/ca-risken/datasource-api/proto/google"
	"github.com/ca-risken/google/pkg/common"
	vulnmodel "github.com/ca-risken/vulnerability/pkg/model"
)

func (s *SqsHandler) putFindings(
	ctx context.Context,
	gcp *google.GCPDataSource,
	it *sccv2.ListFindingsResponse_ListFindingsResultIterator,
) (*int, error) {
	nextPageToken := ""
	counter := 0
	for {
		result, err := s.sccClient.iterationFetchFindingsWithRetry(ctx, it, nextPageToken)
		if err != nil {
			return nil, fmt.Errorf("fetch error: err=%w", err)
		}
		if result == nil || len(result.findings) == 0 {
			break
		}

		findingBatchParam := []*finding.FindingBatchForUpsert{}
		for _, f := range result.findings {
			data, err := s.generateFindingData(ctx, gcp.ProjectId, gcp.GcpProjectId, f)
			if err != nil {
				return nil, fmt.Errorf("generate finding error: err=%w", err)
			}
			findingBatchParam = append(findingBatchParam, data)
		}
		if len(findingBatchParam) > 0 {
			err := grpc_client.PutFindingBatch(ctx, s.findingClient, gcp.ProjectId, findingBatchParam)
			if err != nil {
				return nil, fmt.Errorf("put finding error: err=%w", err)
			}
		}
		counter = counter + len(findingBatchParam)
		if result.token == "" {
			break
		}
		nextPageToken = result.token
	}
	return &counter, nil
}

type SccAsset struct {
	Type               string `json:"type,omitempty"`
	Service            string `json:"service,omitempty"`
	Location           string `json:"location,omitempty"`
	FullName           string `json:"full_name,omitempty"`
	DisplayName        string `json:"display_name,omitempty"`
	ParentDisplayName  string `json:"parent_display_name,omitempty"`
	ProjectDisplayName string `json:"project_display_name,omitempty"`
	Organization       string `json:"organization,omitempty"`
}

type SccFinding struct {
	Asset         *SccAsset                `json:"asset"`
	Finding       *sccv2pb.Finding         `json:"finding"`
	SccDetailURL  string                   `json:"scc_detail_url"`
	Vulnerability *vulnmodel.Vulnerability `json:"vulnerability,omitempty"`
	RiskenTriage  *triage.RiskenTriage     `json:"risken_triage,omitempty"`
}

func (s *SqsHandler) generateFindingData(ctx context.Context, projectID uint32, gcpProjectID string, findingResp *sccv2pb.ListFindingsResponse_ListFindingsResult) (*finding.FindingBatchForUpsert, error) {
	f := findingResp.GetFinding()
	resource := findingResp.GetResource()
	asset := &SccAsset{
		Type:               resource.GetType(),
		Service:            resource.GetService(),
		Location:           resource.GetLocation(),
		FullName:           resource.GetName(),
		DisplayName:        resource.GetDisplayName(),
		ParentDisplayName:  resource.GetGcpMetadata().GetParentDisplayName(),
		ProjectDisplayName: resource.GetGcpMetadata().GetProjectDisplayName(),
		Organization:       resource.GetGcpMetadata().GetOrganization(),
	}

	sccURL := generateSccURL(f.Name, gcpProjectID)
	data := &SccFinding{
		Asset:        asset,
		Finding:      f,
		SccDetailURL: sccURL,
	}
	cve := extractCVEID(f)
	if cve != "" {
		vuln, err := s.GetVulnerability(ctx, cve)
		if err != nil {
			return nil, fmt.Errorf("failed to get vulnerability, project_id=%d, cve_id=%s, err=%+v", projectID, cve, err)
		}
		data.Vulnerability = vuln
		data.RiskenTriage = Triage(vuln, f.AttackExposure)
	}

	buf, err := json.Marshal(data)
	if err != nil {
		s.logger.Errorf(ctx, "failed to marshal user data, project_id=%d, findingName=%s, err=%+v", projectID, f.Name, err)
		return nil, err
	}
	resourceShortName := extractShortResourceName(f.ResourceName)
	findingData := &finding.FindingBatchForUpsert{
		Finding: &finding.FindingForUpsert{
			Description:      generateSccDescrition(f.Category, cve, resourceShortName),
			DataSource:       message.GoogleSCCDataSource,
			DataSourceId:     formatSccDataSourceID(f.Name),
			ResourceName:     f.ResourceName,
			ProjectId:        projectID,
			OriginalScore:    s.scoreSCC(f),
			OriginalMaxScore: 1.0,
			Data:             string(buf),
		},
		Tag: []*finding.FindingTagForBatch{
			{Tag: common.TagGoogle},
			{Tag: common.TagGCP},
			{Tag: common.TagSCC},
			{Tag: riskenstr.TruncateString(gcpProjectID, 64, "")},
			{Tag: riskenstr.TruncateString(common.GetServiceName(f.ResourceName), 64, "")},
		},
	}
	if cve != "" {
		findingData.Tag = append(findingData.Tag, &finding.FindingTagForBatch{Tag: common.TagCVE})
		findingData.Tag = append(findingData.Tag, &finding.FindingTagForBatch{Tag: cve})
	}
	if resourceShortName != "" {
		findingData.Tag = append(findingData.Tag, &finding.FindingTagForBatch{
			Tag: riskenstr.TruncateString(resourceShortName, 64, ""),
		})
	}

	riskDescription := f.Category
	if f.Description != "" {
		riskDescription += "\n" + f.Description
	} else if f.SourceProperties["Explanation"] != nil {
		riskDescription += "\n" + f.SourceProperties["Explanation"].GetStringValue()
	}
	if riskDescription != "" {
		findingData.Recommend = &finding.RecommendForBatch{
			Type: f.Name,
			Risk: riskDescription,
			Recommendation: fmt.Sprintf(`Please see the finding JSON data in 'recommendation' or 'next_steps' field.
And you can see the more information in the Security Command Center console.
- %s`, sccURL),
		}
	}
	return findingData, nil
}

func extractShortResourceName(resourceName string) string {
	array := strings.Split(resourceName, "/")
	if len(array) < 1 {
		return resourceName
	}
	return array[len(array)-1]
}

func extractCVEID(f *sccv2pb.Finding) string {
	if f.Vulnerability != nil && f.Vulnerability.Cve != nil {
		return f.Vulnerability.Cve.Id
	}
	return ""
}

func formatSccDataSourceID(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) < 1 {
		return name
	}

	// Convert API v2 format to API v1 format to maintain compatibility between DataSourceID
	// API v2 format: organizations/111/sources/222/locations/xxx/findings/333
	// API v1 format: organizations/111/sources/222/findings/333
	// Check if the format includes locations part
	if len(parts) >= 7 && parts[4] == "locations" {
		// Remove locations/xxx part
		return fmt.Sprintf("organizations/%s/sources/%s/findings/%s", parts[1], parts[3], parts[7])
	}
	return name
}

func generateSccDescrition(category, cveID, resourceShortName string) string {
	desc := fmt.Sprintf("Detected a %s finding.", category)
	if cveID == "" && resourceShortName == "" {
		return desc
	}

	meta := "("
	if resourceShortName != "" {
		meta += fmt.Sprintf("Resource: %s", resourceShortName)
	}
	if cveID != "" {
		if meta != "(" {
			meta += ", "
		}
		meta += fmt.Sprintf("CVE: %s", cveID)
	}
	meta += ")"
	fullDesc := desc + " " + meta

	// Truncate to 200 characters to avoid RPC error
	return riskenstr.TruncateString(fullDesc, 200, "...")
}

func generateSccURL(name, gcpProjectID string) string {
	encodedName := url.QueryEscape(name)
	return fmt.Sprintf("https://console.cloud.google.com/security/command-center/findingsv2;name=%s?project=%s", encodedName, gcpProjectID)
}
