package main

import (
	"reflect"
	"testing"
)

func TestGetResourceType(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "Exists resource type FirewallRule",
			input: "hoge-fuga-project/instances/instance-name",
			want:  "Firewall",
		},
		{
			name:  "Exists resource type ForwardingRule",
			input: "hoge-fuga-project/ForwardingRule/rule-name",
			want:  "ForwardingRule",
		},
		{
			name:  "Unknown resource type",
			input: "Nmap",
			want:  "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := getResourceType(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data: want=%v, got=%v", c.want, got)
			}
		})
	}
}

func TestGetRecommendType(t *testing.T) {
	cases := []struct {
		name  string
		input [2]string
		want  string
	}{
		{
			name:  "Exists category type Nmap",
			input: [2]string{"Nmap", "ForwardingRule"},
			want:  "ForwardingRule",
		},
		{
			name:  "Exists category type ManyOpen",
			input: [2]string{"ManyOpen", "Firewall"},
			want:  "FirewallPortManyOpen",
		},
		{
			name:  "Unknown category type",
			input: [2]string{"hogefuga", ""},
			want:  "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := getRecommendType(c.input[0], c.input[1])
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data: want=%v, got=%v", c.want, got)
			}
		})
	}
}

func TestGetRecommend(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  recommend
	}{
		{
			name:  "Exists recommend",
			input: "Firewall",
			want: recommend{
				Risk: `Port opens to pubilc
			- Determine if target TCP or UDP port is open to the public
			- While some ports are required to be open to the public to function properly, Restrict to trusted IP addresses.`,
				Recommendation: `Restrict target TCP and UDP port to trusted IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
			},
		},
		{
			name:  "Unknown recommend",
			input: "typeUnknown",
			want: recommend{
				Risk:           "",
				Recommendation: "",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := getRecommend(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data: want=%v, got=%v", c.want, got)
			}
		})
	}
}
