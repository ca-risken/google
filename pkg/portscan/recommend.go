package portscan

import (
	"strings"
)

const (
	categoryNmap               = "Nmap"
	categoryManyOpen           = "ManyOpen"
	categoryFirewallRule       = "Firewall"
	resourceTypeFirewall       = "Firewall"
	resourceTypeFowardingRule  = "ForwardingRule"
	typeFirewallRule           = "Firewall"
	typeForwardingRule         = "ForwardingRule"
	typeManyOpenFirewall       = "FirewallPortManyOpen"
	typeManyOpenForwardingRule = "ForwardingRulePortManyOpen"
)

type recommend struct {
	Risk           string `json:"risk,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
}

func getResourceType(resourceName string) string {
	if strings.Contains(resourceName, "instances") || strings.Contains(resourceName, "firewalls") {
		return resourceTypeFirewall
	} else if strings.Contains(resourceName, "ForwardingRule") {
		return resourceTypeFowardingRule
	}
	return ""
}

func getRecommendType(category, resourceType string) string {
	switch category {
	case categoryNmap, categoryFirewallRule:
		switch resourceType {
		case resourceTypeFowardingRule:
			return typeForwardingRule
		default:
			return typeFirewallRule
		}
	case categoryManyOpen:
		switch resourceType {
		case resourceTypeFowardingRule:
			return typeManyOpenForwardingRule
		default:
			return typeManyOpenFirewall
		}
	default:
		return ""
	}
}

func getRecommend(recommendType string) recommend {
	return recommendMap[recommendType]
}

var recommendMap = map[string]recommend{
	typeFirewallRule: {
		Risk: `Port opens to pubilc
			- Determine if target TCP or UDP port is open to the public
			- While some ports are required to be open to the public to function properly, Restrict to trusted IP addresses.`,
		Recommendation: `Restrict target TCP and UDP port to trusted IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
	},
	typeForwardingRule: {
		Risk: `Port opens to pubilc
			- Determine if target TCP or UDP port is open to the public
			- While some ports are required to be open to the public to function properly, Restrict to trusted IP addresses.`,
		Recommendation: `Restrict target port to trusted IP addresses by Google Cloud Armor.
			- https://cloud.google.com/armor/docs/security-policy-overview`,
	},
	typeManyOpenFirewall: {
		Risk: `Open Many Ports
			- Determine if security group has many ports open to the public
			- Security groups should be created on a per-service basis and restrict to trusted IP addresses.`,
		Recommendation: `Modify the security group to specify a specific port and and restrict to trusted IP addresses.
		- https://cloud.google.com/vpc/docs/using-firewalls`,
	},
	typeManyOpenForwardingRule: {
		Risk: `Open Many Ports
			- Determine if security group has many ports open to the public
			- Security groups should be created on a per-service basis and restrict to trusted IP addresses.`,
		Recommendation: `Restrict target port to trusted IP addresses by Google Cloud Armor.
			- https://cloud.google.com/armor/docs/security-policy-overview`,
	},
}
