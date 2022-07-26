package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ca-risken/common/pkg/portscan"
	"github.com/vikyd/zero"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

type portscanServiceClient interface {
	listTarget(ctx context.Context, gcpProjectID string) ([]*target, map[string]*relFirewallResource, error)
	excludeTarget(targets []*target) ([]*target, []*exclude)
}

type portscanClient struct {
	compute               *compute.Service
	ScanExcludePortNumber int
}

func newPortscanClient(credentialPath string, scanExcludePortNumber int) (portscanServiceClient, error) {
	ctx := context.Background()
	compute, err := compute.NewService(ctx, option.WithCredentialsFile(credentialPath))
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate for Compute service: %w", err)
	}

	// Remove credential file for Security
	if err := os.Remove(credentialPath); err != nil {
		return nil, fmt.Errorf("failed to remove file: path=%s, err=%w", credentialPath, err)
	}
	return &portscanClient{
		compute:               compute,
		ScanExcludePortNumber: scanExcludePortNumber,
	}, nil
}

func (p *portscanClient) listTarget(ctx context.Context, gcpProjectID string) ([]*target, map[string]*relFirewallResource, error) {
	var ret []*target
	infFirewalls, relFirewallResource, err := listTargetFirewall(ctx, p.compute, gcpProjectID)
	if err != nil {
		appLogger.Errorf(ctx, "Failed to describe firewall service: %+v", err)
		return nil, nil, err
	}
	if infFirewalls == nil && relFirewallResource == nil {
		return nil, nil, nil
	}

	infComputes, err := listTargetCompute(ctx, p.compute, gcpProjectID)
	if err != nil {
		appLogger.Errorf(ctx, "Failed to describe compute service: %+v", err)
		return nil, nil, err
	}

	infForwardings, err := listTargetForwardingRule(ctx, p.compute, gcpProjectID)
	if err != nil {
		appLogger.Errorf(ctx, "Failed to describe compute service: %+v", err)
		return nil, nil, err
	}

	for _, firewall := range infFirewalls {
		for _, infCompute := range infComputes {
			if matchFirewallCompute(firewall, infCompute) {
				for _, targetPort := range firewall.Ports {
					for _, port := range targetPort.Ports {
						fromPort, toPort, err := splitPort(ctx, port)
						if err != nil {
							return nil, nil, err
						}
						ret = append(ret, &target{
							ResourceName:     infCompute.ResourceName,
							FirewallRuleName: firewall.ResourceName,
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

	addRelFirewllResources(relFirewallResource, infComputes)

	for _, forwarding := range infForwardings {
		fromPort, toPort, err := splitPort(ctx, forwarding.PortRange)
		if err != nil {
			return nil, nil, err
		}
		ret = append(ret, &target{
			ResourceName: forwarding.ResourceName,
			FromPort:     fromPort,
			ToPort:       toPort,
			Target:       forwarding.IPAddress,
			Protocol:     forwarding.IPProtocol,
			Type:         "ForwardingRule",
		})
	}
	return ret, relFirewallResource, nil
}

func listTargetFirewall(ctx context.Context, com *compute.Service, gcpProjectID string) ([]*infoFirewall, map[string]*relFirewallResource, error) {
	firewalls := compute.NewFirewallsService(com)
	var ret []*infoFirewall
	relFirewallResources := map[string]*relFirewallResource{}
	// https://pkg.go.dev/google.golang.org/api/compute/v1#FirewallsListCall.Do
	f, err := firewalls.List(gcpProjectID).Do()
	if err != nil {
		appLogger.Errorf(ctx, "Failed to list firewall rules: %+v", err)
		return nil, nil, handleGoogleAPIError(ctx, err)
	}
	for _, fItem := range f.Items {
		relFirewallResources[getFullResourceName(ctx, fItem.SelfLink)] = &relFirewallResource{
			Firewall: fItem,
			IsPublic: hasFullOpenRange(fItem.SourceRanges),
		}
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
			Ports:        ports,
			Name:         fItem.Name,
			Network:      fItem.Network,
			ResourceName: getFullResourceName(ctx, fItem.SelfLink),
			TargetTags:   fItem.TargetTags,
		})
	}
	return ret, relFirewallResources, nil
}

func handleGoogleAPIError(ctx context.Context, err error) error {
	var gerr *googleapi.Error
	ok := errors.As(err, &gerr)
	if !ok {
		return err
	}
	for _, detail := range gerr.Details {
		dmap, ok := detail.(map[string]interface{})
		if !ok {
			continue
		}
		errType, ok := dmap["@type"].(string)
		if !ok {
			continue
		}
		errReason, ok := dmap["reason"].(string)
		if !ok {
			continue
		}
		if errType == "type.googleapis.com/google.rpc.ErrorInfo" && errReason == "SERVICE_DISABLED" {
			appLogger.Debugf(ctx, "Compute API is not enabled for this project, error_detail=%+v", dmap)
			return nil // no error
		}
	}
	return err
}

func listTargetCompute(ctx context.Context, com *compute.Service, gcpProjectID string) ([]*infoCompute, error) {
	instances := compute.NewInstancesService(com)
	i, err := instances.AggregatedList(gcpProjectID).Do()
	if err != nil {
		appLogger.Errorf(ctx, "Failed to describe Compute service: %+v", err)
		return nil, err
	}
	var ret []*infoCompute
	for _, itemPerZone := range i.Items {
		for _, instance := range itemPerZone.Instances {
			for _, networkInterface := range instance.NetworkInterfaces {
				for _, accessConfig := range networkInterface.AccessConfigs {
					ret = append(ret, &infoCompute{
						NatIP:                accessConfig.NatIP,
						Name:                 instance.Name,
						ResourceName:         getFullResourceName(ctx, instance.SelfLink),
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

func listTargetForwardingRule(ctx context.Context, com *compute.Service, gcpProjectID string) ([]*infoForwardingRule, error) {
	forwardings := compute.NewForwardingRulesService(com)
	fw, err := forwardings.AggregatedList(gcpProjectID).Do()
	if err != nil {
		appLogger.Errorf(ctx, "Failed to list forwarding rules: %+v", err)
		return nil, err
	}
	var ret []*infoForwardingRule
	for _, forwardingRulesScopedList := range fw.Items {
		for _, fr := range forwardingRulesScopedList.ForwardingRules {
			if fr.LoadBalancingScheme != "EXTERNAL" || (fr.IPProtocol != "TCP" && fr.IPProtocol != "UDP") {
				continue
			}
			ret = append(ret, &infoForwardingRule{
				IPAddress:    fr.IPAddress,
				PortRange:    fr.PortRange,
				Network:      fr.Network,
				Name:         fmt.Sprintf("%v/%v/%v", gcpProjectID, "ForwardingRule", fr.Name),
				ResourceName: getFullResourceName(ctx, fr.SelfLink),
				IpVersion:    fr.IpVersion,
				IPProtocol:   fr.IPProtocol,
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

func addRelFirewllResources(relFirewallResources map[string]*relFirewallResource, computes []*infoCompute) {
	for resourceName, r := range relFirewallResources {
		for _, c := range computes {
			if r.Firewall.Network != c.Network {
				continue
			}
			if zero.IsZeroVal(r.Firewall.TargetTags) {
				relFirewallResources[resourceName].ReferenceResources = append(relFirewallResources[resourceName].ReferenceResources, c.ResourceName)
			} else {
				for _, instanceTag := range c.Tags {
					for _, firewallTag := range r.Firewall.TargetTags {
						if instanceTag == firewallTag {
							relFirewallResources[resourceName].ReferenceResources = append(relFirewallResources[resourceName].ReferenceResources, c.ResourceName)
						}
					}
				}
			}
		}
	}
}

func hasFullOpenRange(ranges []string) bool {
	for _, sourceRange := range ranges {
		if sourceRange == "0.0.0.0/0" {
			return true
		}
	}
	return false
}

func scan(ctx context.Context, target *target) ([]*portscan.NmapResult, error) {
	results, err := portscan.Scan(target.Target, target.Protocol, target.FromPort, target.ToPort)
	if err != nil {
		appLogger.Errorf(ctx, "Error occured when scanning. err: %v", err)
		return nil, err
	}
	var ret []*portscan.NmapResult
	for _, result := range results {
		result.ResourceName = target.ResourceName
		ret = append(ret, result)
	}
	return ret, nil
}

func splitPort(ctx context.Context, port string) (int, int, error) {
	var fromPortStr string
	var toPortStr string
	if !strings.Contains(port, "-") {
		fromPortStr = port
		toPortStr = port
	} else {
		sPort := strings.Split(port, "-")
		fromPortStr = sPort[0]
		toPortStr = sPort[1]
	}
	fromPort, err := strconv.Atoi(fromPortStr)
	if err != nil {
		appLogger.Errorf(ctx, "Unexpected Port Number is set. port=%v, err=%+v", fromPort, err)
		return 0, 0, err
	}
	toPort, err := strconv.Atoi(toPortStr)
	if err != nil {
		appLogger.Errorf(ctx, "Unexpected Port Number is set. port=%v, err=%+v", toPort, err)
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

func getFullResourceName(ctx context.Context, selfLink string) string {
	array := strings.Split(strings.Replace(selfLink, "//", "", 1), "/")
	if len(array) < 4 {
		appLogger.Warnf(ctx, "Failed to Get Full Resource Name. selfLink: %v", selfLink)
		return selfLink
	}
	apiService := fmt.Sprintf("%v.googleapis.com", array[1])
	resource := strings.Join(array[3:], "/")
	appLogger.Infof(ctx, "FullResourceName: %v", fmt.Sprintf("//%v/%v", apiService, resource))
	return fmt.Sprintf("//%v/%v", apiService, resource)

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

type relFirewallResource struct {
	Firewall           *compute.Firewall `json:"firewall"`
	ReferenceResources []string          `json:"resources"`
	IsPublic           bool              `json:"is_public"`
}

type targetPort struct {
	Protocol string
	Ports    []string
}

type infoFirewall struct {
	Ports        []targetPort
	Name         string
	Network      string
	ResourceName string
	TargetTags   []string
}

type infoCompute struct {
	ID                   string
	Name                 string
	Network              string
	NatIP                string
	NetworkInterfaceName string
	Tags                 []string
	ResourceName         string
}

type infoForwardingRule struct {
	IPAddress    string
	Name         string
	ResourceName string
	PortRange    string
	IpVersion    string
	Network      string
	IPProtocol   string
}
