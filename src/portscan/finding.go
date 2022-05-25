package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/ca-risken/common/pkg/portscan"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/google/pkg/common"
	"github.com/vikyd/zero"
)

func (s *sqsHandler) putNmapFindings(ctx context.Context, projectID uint32, gcpProjectID string, nmapResult *portscan.NmapResult) error {
	externalLink := makeURL(nmapResult.Target, nmapResult.Port)
	data, err := json.Marshal(map[string]interface{}{"data": *nmapResult, "external_link": externalLink})
	if err != nil {
		return err
	}
	findings := nmapResult.GetFindings(projectID, common.PortscanDataSource, string(data))
	tags := nmapResult.GetTags()
	tags = append(tags, gcpProjectID)
	err = s.putFindings(ctx, findings, tags, categoryNmap)
	if err != nil {
		return fmt.Errorf("putNmapFinding error. gcpProjectID:%v, tags: %v, err: %v", gcpProjectID, tags, err)
	}
	return nil
}

func (s *sqsHandler) putExcludeFindings(ctx context.Context, gcpProjectID string, excludeList []*exclude, message *common.GCPQueueMessage) error {
	var findings []*finding.FindingForUpsert
	for _, e := range excludeList {
		data, err := json.Marshal(map[string]exclude{"data": *e})
		if err != nil {
			return err
		}
		finding := &finding.FindingForUpsert{
			Description:      e.getDescription(),
			DataSource:       common.PortscanDataSource,
			DataSourceId:     generateDataSourceID(fmt.Sprintf("%v:%v:%v", e.Target, e.Protocol, e.ResourceName)),
			ResourceName:     e.ResourceName,
			ProjectId:        message.ProjectID,
			OriginalScore:    6.0,
			OriginalMaxScore: 10.0,
			Data:             string(data),
		}
		findings = append(findings, finding)
	}
	err := s.putFindings(ctx, findings, []string{gcpProjectID}, categoryManyOpen)
	if err != nil {
		return err
	}

	return nil
}

func (s *sqsHandler) putRelFirewallResourceFindings(ctx context.Context, gcpProjectID string, relFirewallResourceMap map[string]*relFirewallResource, message *common.GCPQueueMessage) error {
	var findings []*finding.FindingForUpsert
	for resourceName, r := range relFirewallResourceMap {
		data, err := json.Marshal(r)
		if err != nil {
			return err
		}
		score := float32(1.0)
		if r.IsPublic {
			score = 3.0
		}
		findings = append(findings, &finding.FindingForUpsert{
			Description:      getFirewallRuleDescription(resourceName, r.IsPublic),
			DataSource:       common.PortscanDataSource,
			DataSourceId:     generateDataSourceID(fmt.Sprintf("%v:portscan_firewall:%v", gcpProjectID, resourceName)),
			ResourceName:     resourceName,
			ProjectId:        message.ProjectID,
			OriginalScore:    score,
			OriginalMaxScore: 10.0,
			Data:             string(data),
		})
	}
	tags := []string{gcpProjectID, "compute", "firewall"}

	err := s.putFindings(ctx, findings, tags, categoryManyOpen)
	if err != nil {
		return err
	}

	return nil
}

func (s *sqsHandler) putFindings(ctx context.Context, findings []*finding.FindingForUpsert, additionalTags []string, recommendCategory string) error {
	for _, f := range findings {
		res, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{Finding: f})
		if err != nil {
			return err
		}
		if err := s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, common.TagGoogle); err != nil {
			return err
		}
		if err := s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, common.TagGCP); err != nil {
			return err
		}
		if err := s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, common.TagPortscan); err != nil {
			return err
		}
		for _, additionalTag := range additionalTags {
			if err := s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, additionalTag); err != nil {
				return err
			}
		}
		if err = s.putRecommend(ctx, res.Finding.ProjectId, res.Finding.FindingId, recommendCategory, res.Finding.ResourceName); err != nil {
			appLogger.Errorf(ctx, "Failed to put recommend project_id=%d, finding_id=%d, category=%s, err=%+v",
				res.Finding.ProjectId, res.Finding.FindingId, recommendCategory, err)
			return err
		}
	}
	return nil
}

func (s *sqsHandler) putRecommend(ctx context.Context, projectID uint32, findingID uint64, recommendCategory, resourceName string) error {
	resourceType := getResourceType(resourceName)
	if zero.IsZeroVal(resourceType) {
		appLogger.Warnf(ctx, "Failed to get resource type, Unknown category,resource_name=%s", fmt.Sprintf("%v", resourceName))
		return nil
	}
	recommendType := getRecommendType(recommendCategory, resourceType)
	if zero.IsZeroVal(recommendType) {
		appLogger.Warnf(ctx, "Failed to get recommendation type, Unknown category,resource_type=%s", fmt.Sprintf("%v:%v", recommendCategory, resourceType))
		return nil
	}
	r := getRecommend(recommendType)
	if r.Risk == "" && r.Recommendation == "" {
		appLogger.Warnf(ctx, "Failed to get recommendation, Unknown reccomendType,service=%s", fmt.Sprintf("%v", recommendType))
		return nil
	}
	if _, err := s.findingClient.PutRecommend(ctx, &finding.PutRecommendRequest{
		ProjectId:      projectID,
		FindingId:      findingID,
		DataSource:     common.PortscanDataSource,
		Type:           recommendType,
		Risk:           r.Risk,
		Recommendation: r.Recommendation,
	}); err != nil {
		return err
	}
	return nil
}

func (s *sqsHandler) tagFinding(ctx context.Context, projectID uint32, findingID uint64, tag string) error {
	if _, err := s.findingClient.TagFinding(ctx, &finding.TagFindingRequest{
		ProjectId: projectID,
		Tag: &finding.FindingTagForUpsert{
			FindingId: findingID,
			ProjectId: projectID,
			Tag:       tag,
		}}); err != nil {
		return fmt.Errorf("Failed to TagFinding. error: %v", err)
	}
	return nil
}

func generateDataSourceID(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

func (e *exclude) getDescription() string {
	if e.FirewallRuleName != "" {
		return fmt.Sprintf("Too many ports are exposed.target:%v protocol: %v, port %v-%v,firewall_rule: %v", e.Target, e.Protocol, e.FromPort, e.ToPort, e.FirewallRuleName)
	}
	return fmt.Sprintf("Too many ports are exposed.target:%v protocol: %v, port %v-%v", e.Target, e.Protocol, e.FromPort, e.ToPort)
}

func getFirewallRuleDescription(firewallResource string, isPublic bool) string {
	return fmt.Sprintf("firewall rule was found. resource name: %v, Public: %v", firewallResource, isPublic)
}

func makeURL(target string, port int) string {
	switch port {
	case 443:
		return fmt.Sprintf("https://%v", target)
	case 80:
		return fmt.Sprintf("http://%v", target)
	default:
		return fmt.Sprintf("http://%v:%v", target, port)
	}
}
