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

func makeFinding(result *portscan.NmapResult, message *common.GCPQueueMessage) (*finding.FindingForUpsert, error) {
	data, err := json.Marshal(map[string]portscan.NmapResult{"data": *result})
	if err != nil {
		return nil, err
	}
	finding := &finding.FindingForUpsert{
		Description:      result.GetDescription(),
		DataSource:       common.PortscanDataSource,
		DataSourceId:     result.GetDataSourceID(),
		ResourceName:     result.ResourceName,
		ProjectId:        message.ProjectID,
		OriginalScore:    result.GetScore(),
		OriginalMaxScore: 10.0,
		Data:             string(data),
	}
	return finding, nil
}

func makeExcludeFinding(result *exclude, message *common.GCPQueueMessage) (*finding.FindingForUpsert, error) {
	data, err := json.Marshal(map[string]exclude{"data": *result})
	if err != nil {
		return nil, err
	}
	finding := &finding.FindingForUpsert{
		Description:      result.getDescription(),
		DataSource:       common.PortscanDataSource,
		DataSourceId:     result.getDataSourceID(),
		ResourceName:     result.ResourceName,
		ProjectId:        message.ProjectID,
		OriginalScore:    6.0,
		OriginalMaxScore: 10.0,
		Data:             string(data),
	}
	return finding, nil
}

func (s *sqsHandler) putFindings(ctx context.Context, findings []*finding.FindingForUpsert) error {
	for _, f := range findings {

		res, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{Finding: f})
		if err != nil {
			return err
		}
		s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, common.TagGCP)
		s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, common.TagPortscan)
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
