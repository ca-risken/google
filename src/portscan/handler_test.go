package main

import (
	"reflect"
	"testing"
)

func TestHasFullOpenRange(t *testing.T) {
	cases := []struct {
		name  string
		input []string
		want  bool
	}{
		{
			name:  "OK",
			input: []string{"10.1.1.1/27", "0.0.0.0/0", "192.168.0.1/24"},
			want:  true,
		},
		{
			name:  "NO",
			input: []string{"10.1.1.1/27", "0.0.0.0/1", "192.168.0.1/24"},
			want:  false,
		},
		{
			name:  "No(input empty)",
			input: []string{""},
			want:  false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := hasFullOpenRange(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestSplitPort(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantFrom int
		wantTo   int
		isErr    bool
	}{
		{
			name:     "OK 1 port",
			input:    "80",
			wantFrom: 80,
			wantTo:   80,
			isErr:    false,
		},
		{
			name:     "OK port range",
			input:    "80-443",
			wantFrom: 80,
			wantTo:   443,
			isErr:    false,
		},
		{
			name:     "NG invalid char range",
			input:    "8a-443",
			wantFrom: 0,
			wantTo:   0,
			isErr:    true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fromPort, toPort, err := splitPort(c.input)
			if !reflect.DeepEqual(c.wantFrom, fromPort) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.wantFrom, fromPort)
			}
			if !reflect.DeepEqual(c.wantFrom, fromPort) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.wantTo, toPort)
			}
			if !c.isErr && err != nil {
				t.Fatalf("Unexpected error occured: err=%+v", err)
			}
		})
	}
}

func TestGtFullResourceName(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "get firewall resource name",
			input: "https://www.googleapis.com/compute/v1/projects/PROJECT_ID/global/firewalls/FIREWALL",
			want:  "//compute.googleapis.com/projects/PROJECT_ID/global/firewalls/FIREWALL",
		},
		{
			name:  "get instance resource name",
			input: "https://compute.googleapis.com/compute/v1/projects/PROJECT_ID/zones/ZONE/instances/INSTANCE",
			want:  "//compute.googleapis.com/projects/PROJECT_ID/zones/ZONE/instances/INSTANCE",
		},
		{
			name:  "get forwarding rule resource name",
			input: "https://www.googleapis.com/compute/v1/projects/PROJECT_ID/regions/REGION/forwardingRules/FORWARDING_RULE",
			want:  "//compute.googleapis.com/projects/PROJECT_ID/regions/REGION/forwardingRules/FORWARDING_RULE",
		},
		{
			name:  "incomplete format",
			input: "imcomplete format",
			want:  "imcomplete format",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := getFullResourceName(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
