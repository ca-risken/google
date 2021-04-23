package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/CyberAgent/mimosa-common/pkg/portscan"
	"github.com/CyberAgent/mimosa-core/proto/finding"
	"github.com/CyberAgent/mimosa-google/pkg/common"
)

func (s *sqsHandler) putNmapFindings(ctx context.Context, projectID uint32, nmapResult *portscan.NmapResult) error {
	data, err := json.Marshal(map[string]portscan.NmapResult{"data": *nmapResult})
	if err != nil {
		return err
	}
	findings := nmapResult.GetFindings(projectID, common.PortscanDataSource, string(data))
	tags := nmapResult.GetTags()
	err = s.putFindings(ctx, findings, tags)
	if err != nil {
		return err
	}
	return nil
}

func (s *sqsHandler) putExcludeFindings(ctx context.Context, excludeList []*exclude, message *common.GCPQueueMessage) error {
	var findings []*finding.FindingForUpsert
	for _, e := range excludeList {
		data, err := json.Marshal(map[string]exclude{"data": *e})
		if err != nil {
			return err
		}
		finding := &finding.FindingForUpsert{
			Description:      e.getDescription(),
			DataSource:       common.PortscanDataSource,
			DataSourceId:     e.getDataSourceID(),
			ResourceName:     e.ResourceName,
			ProjectId:        message.ProjectID,
			OriginalScore:    6.0,
			OriginalMaxScore: 10.0,
			Data:             string(data),
		}
		findings = append(findings, finding)
	}
	err := s.putFindings(ctx, findings, []string{})
	if err != nil {
		return err
	}

	return nil
}

func (s *sqsHandler) putFindings(ctx context.Context, findings []*finding.FindingForUpsert, additionalTags []string) error {
	for _, f := range findings {
		res, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{Finding: f})
		if err != nil {
			return err
		}
		s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, common.TagGCP)
		s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, common.TagPortscan)
		for _, additionalTag := range additionalTags {
			s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, additionalTag)
		}
	}

	return nil
}

func (s *sqsHandler) tagFinding(ctx context.Context, projectID uint32, findingID uint64, tag string) error {

	_, err := s.findingClient.TagFinding(ctx, &finding.TagFindingRequest{
		ProjectId: projectID,
		Tag: &finding.FindingTagForUpsert{
			FindingId: findingID,
			ProjectId: projectID,
			Tag:       tag,
		}})
	if err != nil {
		appLogger.Errorf("Failed to TagFinding. error: %v", err)
		return err
	}
	return nil
}

func (e *exclude) getDataSourceID() string {
	input := fmt.Sprintf("%v:%v:%v", e.Target, e.Protocol, e.ResourceName)
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

func (e *exclude) getDescription() string {
	if e.FirewallRuleName != "" {
		return fmt.Sprintf("Too many ports are exposed.target:%v protocol: %v, port %v-%v,firewall_rule: %v", e.Target, e.Protocol, e.FromPort, e.ToPort, e.FirewallRuleName)
	}
	return fmt.Sprintf("Too many ports are exposed.target:%v protocol: %v, port %v-%v", e.Target, e.Protocol, e.FromPort, e.ToPort)
}
