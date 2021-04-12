package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	portscan "github.com/CyberAgent/mimosa-common/pkg/portscan"
	"github.com/kelseyhightower/envconfig"
	"github.com/vikyd/zero"
	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

type portscanServiceClient interface {
	//	listAppEngine(ctx context.Context, gcpProjectID string) *appengine.InstanceIterator
	listTarget(ctx context.Context, gcpProjectID string) ([]*target, error)
	excludeTarget(targets []*target) ([]*target, []*exclude)
}

type portscanClient struct {
	//	appEngine *appengine.Client
	compute               *compute.Service
	ScanExcludePortNumber int
}

type portscanConfig struct {
	GoogleCredentialPath  string `required:"true" split_words:"true"`
	ScanExcludePortNumber int    `default:"1000" split_words:"true"`
}

func newPortscanClient() portscanServiceClient {
	var conf portscanConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatalf("Could not read config. err: %+v", err)
	}
	ctx := context.Background()
	//	ae, err := appengine.NewClient(ctx, option.WithCredentialsFile(conf.GoogleCredentialPath))
	//	if err != nil {
	//		appLogger.Fatalf("Failed to authenticate for AppEngine API client: %+v", err)
	//	}
	compute, err := compute.NewService(ctx, option.WithCredentialsFile(conf.GoogleCredentialPath))
	if err != nil {
		appLogger.Fatalf("Failed to authenticate for Compute service: %+v", err)
	}

	// Remove credential file for Security
	if err := os.Remove(conf.GoogleCredentialPath); err != nil {
		appLogger.Fatalf("Failed to remove file: path=%s, err=%+v", conf.GoogleCredentialPath, err)
	}
	return &portscanClient{
		//		appEngine: ae,
		compute:               compute,
		ScanExcludePortNumber: conf.ScanExcludePortNumber,
	}
}

//func (p *portscanClient) listInstances(ctx context.Context, gcpProjectID string) *appengine.InstanceIterator {
//	return p.appEngine.ListInstances(ctx, &appenginepb.ListInstancesRequest{
//		Scope: "projects/" + gcpProjectID,
//	})
//}

func (p *portscanClient) listTarget(ctx context.Context, gcpProjectID string) ([]*target, error) {
	var ret []*target
	infFirewalls, err := listTargetFirewall(p.compute, gcpProjectID)
	if err != nil {
		appLogger.Fatalf("Failed to describe firewall service: %+v", err)
		return nil, err
	}

	infComputes, err := listTargetCompute(p.compute, gcpProjectID)
	if err != nil {
		appLogger.Fatalf("Failed to describe compute service: %+v", err)
		return nil, err
	}

	infForwardings, err := listTargetForwardingRule(p.compute, gcpProjectID)
	if err != nil {
		appLogger.Fatalf("Failed to describe compute service: %+v", err)
		return nil, err
	}

	for _, firewall := range infFirewalls {
		for _, infCompute := range infComputes {
			if matchFirewallCompute(firewall, infCompute) {
				for _, targetPort := range firewall.Ports {
					for _, port := range targetPort.Ports {
						fromPort, toPort, err := splitPort(port)
						if err != nil {
							return nil, err
						}
						ret = append(ret, &target{
							ResourceName:     fmt.Sprintf("%v/%v/%v", gcpProjectID, "instances", infCompute.ID),
							FirewallRuleName: firewall.Name,
							FromPort:         fromPort,
							ToPort:           toPort,
							Protocol:         targetPort.Protocol,
							Target:           infCompute.NatIP,
							Type:             "compute",
						})
					}
				}
			}
		}
	}

	for _, forwarding := range infForwardings {
		fromPort, toPort, err := splitPort(forwarding.PortRange)
		if err != nil {
			return nil, err
		}
		ret = append(ret, &target{
			ResourceName: forwarding.Name,
			FromPort:     fromPort,
			ToPort:       toPort,
			Target:       forwarding.IPAddress,
			Protocol:     forwarding.IPProtocol,
			Type:         "ForwardingRule",
		})
	}
	return ret, nil
}

func listTargetFirewall(com *compute.Service, gcpProjectID string) ([]*infoFirewall, error) {
	firewalls := compute.NewFirewallsService(com)
	var ret []*infoFirewall
	f, err := firewalls.List(gcpProjectID).Do()
	if err != nil {
		appLogger.Fatalf("Failed to list firewall rules: %+v", err)
		return nil, err
	}
	for _, fItem := range f.Items {
		if fItem.Direction != "INGRESS" || fItem.Disabled || !hasFullOpenRange(fItem.SourceRanges) {
			continue
		}
		var ports []targetPort
		for _, allowed := range fItem.Allowed {
			switch allowed.IPProtocol {
			case "tcp", "udp":
				ports = append(ports, targetPort{
					Protocol: allowed.IPProtocol,
					Ports:    allowed.Ports,
				})
			case "all":
				ports = append(ports, targetPort{
					Protocol: "tcp",
					Ports:    []string{"0-65535"},
				})
				ports = append(ports, targetPort{
					Protocol: "udp",
					Ports:    []string{"0-65535"},
				})
			}
		}
		if zero.IsZeroVal(ports) {
			continue
		}
		ret = append(ret, &infoFirewall{
			Ports:      ports,
			Name:       fItem.Name,
			Network:    fItem.Network,
			TargetTags: fItem.TargetTags,
		})
	}
	return ret, nil
}

func listTargetCompute(com *compute.Service, gcpProjectID string) ([]*infoCompute, error) {
	instances := compute.NewInstancesService(com)
	i, err := instances.AggregatedList(gcpProjectID).Do()
	if err != nil {
		appLogger.Fatalf("Failed to describe Compute service: %+v", err)
		return nil, err
	}
	var ret []*infoCompute
	//	appLogger.Infof("instances: %v", i)
	for _, itemPerZone := range i.Items {
		for _, instance := range itemPerZone.Instances {
			for _, networkInterface := range instance.NetworkInterfaces {
				for _, accessConfig := range networkInterface.AccessConfigs {
					ret = append(ret, &infoCompute{
						NatIP:                accessConfig.NatIP,
						ID:                   strconv.FormatUint(instance.Id, 10),
						Network:              networkInterface.Network,
						NetworkInterfaceName: networkInterface.Name,
						Tags:                 instance.Tags.Items,
					})
				}
			}
		}
	}
	return ret, nil
}

func listTargetForwardingRule(com *compute.Service, gcpProjectID string) ([]*infoForwardingRule, error) {
	forwardings := compute.NewForwardingRulesService(com)
	fw, err := forwardings.AggregatedList(gcpProjectID).Do()
	if err != nil {
		appLogger.Fatalf("Failed to list forwarding rules: %+v", err)
		return nil, err
	}
	var ret []*infoForwardingRule
	for _, forwardingRulesScopedList := range fw.Items {
		for _, fr := range forwardingRulesScopedList.ForwardingRules {
			if fr.LoadBalancingScheme != "EXTERNAL" || (fr.IPProtocol != "TCP" && fr.IPProtocol != "UDP") {
				continue
			}
			ret = append(ret, &infoForwardingRule{
				IPAddress:  fr.IPAddress,
				PortRange:  fr.PortRange,
				Network:    fr.Network,
				Name:       fmt.Sprintf("%v/%v/%v", gcpProjectID, "ForwardingRule", fr.Name),
				IpVersion:  fr.IpVersion,
				IPProtocol: fr.IPProtocol,
			})
		}
	}
	return ret, nil
}

func matchFirewallCompute(firewall *infoFirewall, instance *infoCompute) bool {
	if firewall.Network != instance.Network {
		return false
	}
	if zero.IsZeroVal(firewall.TargetTags) {
		return true
	}
	for _, instanceTag := range instance.Tags {
		for _, firewallTag := range firewall.TargetTags {
			if instanceTag == firewallTag {
				return true
			}
		}
	}
	return false
}

func hasFullOpenRange(ranges []string) bool {
	for _, sourceRange := range ranges {
		if sourceRange == "0.0.0.0/0" {
			return true
		}
	}
	return false
}

func scan(target *target) []*portscan.NmapResult {
	results, err := portscan.Scan(target.Target, target.Protocol, target.FromPort, target.ToPort)
	if err != nil {
		appLogger.Warnf("Error occured when scanning. err: %v", err)
		return nil
	}
	var ret []*portscan.NmapResult
	for _, result := range results {
		result.ResourceName = target.ResourceName
		ret = append(ret, result)
	}
	return ret
}

func splitPort(port string) (int, int, error) {
	var fromPortStr string
	var toPortStr string
	if strings.Index(port, "-") < 0 {
		fromPortStr = port
		toPortStr = port
	} else {
		sPort := strings.Split(port, "-")
		fromPortStr = sPort[0]
		toPortStr = sPort[1]
	}
	fromPort, err := strconv.Atoi(fromPortStr)
	if err != nil {
		appLogger.Errorf("Unexpected Port Number is set. port=%v, err=%+v", fromPort, err)
		return 0, 0, err
	}
	toPort, err := strconv.Atoi(toPortStr)
	if err != nil {
		appLogger.Errorf("Unexpected Port Number is set. port=%v, err=%+v", toPort, err)
		return 0, 0, err
	}
	return fromPort, toPort, nil
}

func (p *portscanClient) excludeTarget(targets []*target) ([]*target, []*exclude) {
	var scanTarget []*target
	var excludeList []*exclude
	for _, target := range targets {
		if (target.ToPort - target.FromPort) >= p.ScanExcludePortNumber {
			excludeList = append(excludeList, &exclude{
				Target:           target.Target,
				FromPort:         target.FromPort,
				ToPort:           target.ToPort,
				Protocol:         target.Protocol,
				ResourceName:     target.ResourceName,
				FirewallRuleName: target.FirewallRuleName,
			})

		} else {
			scanTarget = append(scanTarget, target)
		}
	}
	return scanTarget, excludeList
}

type target struct {
	Target           string
	FromPort         int
	ToPort           int
	Protocol         string
	ResourceName     string
	FirewallRuleName string
	Type             string
}

type exclude struct {
	Target           string
	FromPort         int
	ToPort           int
	Protocol         string
	ResourceName     string
	FirewallRuleName string
}

type targetPort struct {
	Protocol string
	Ports    []string
}

type infoFirewall struct {
	Ports      []targetPort
	Name       string
	Network    string
	TargetTags []string
}

type infoCompute struct {
	ID                   string
	Network              string
	NatIP                string
	NetworkInterfaceName string
	Tags                 []string
}

type infoForwardingRule struct {
	IPAddress  string
	Name       string
	PortRange  string
	IpVersion  string
	Network    string
	IPProtocol string
}
