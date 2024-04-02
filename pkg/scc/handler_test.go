package scc

import (
	"testing"

	sccpb "cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
)

func TestExtractShortResourceName(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "Full resource name",
			input: "//container.googleapis.com/projects/my-project/locations/region-code/clusters/my-cluster",
			want:  "my-cluster",
		},
		{
			name:  "Short resource name",
			input: "my-cluster",
			want:  "my-cluster",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractShortResourceName(c.input)
			if c.want != got {
				t.Fatalf("Unexpected: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestExtractCVEID(t *testing.T) {
	cases := []struct {
		name  string
		input *sccpb.Finding
		want  string
	}{
		{
			name: "OK",
			input: &sccpb.Finding{
				Vulnerability: &sccpb.Vulnerability{
					Cve: &sccpb.Cve{
						Id: "CVE-2020-1234",
					},
				},
			},
			want: "CVE-2020-1234",
		},
		{
			name:  "Empty Finding",
			input: &sccpb.Finding{},
			want:  "",
		},
		{
			name: "No Vulnerability",
			input: &sccpb.Finding{
				Vulnerability: nil,
			},
			want: "",
		},
		{
			name: "No CVE",
			input: &sccpb.Finding{
				Vulnerability: &sccpb.Vulnerability{
					Cve: nil,
				},
			},
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractCVEID(c.input)
			if c.want != got {
				t.Fatalf("Unexpected: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestGenerateSccDescrition(t *testing.T) {
	type args struct {
		category          string
		cveID             string
		resourceShortName string
	}
	cases := []struct {
		name  string
		input args
		want  string
	}{
		{
			name: "OK",
			input: args{
				category:          "SOME_CATEGORY",
				cveID:             "CVE-2020-1234",
				resourceShortName: "my-cluster",
			},
			want: "Detected a SOME_CATEGORY finding. (Resource: my-cluster, CVE: CVE-2020-1234)",
		},
		{
			name: "Without Resource",
			input: args{
				category:          "SOME_CATEGORY",
				cveID:             "CVE-2020-1234",
				resourceShortName: "",
			},
			want: "Detected a SOME_CATEGORY finding. (CVE: CVE-2020-1234)",
		},
		{
			name: "Without CVE",
			input: args{
				category:          "SOME_CATEGORY",
				cveID:             "",
				resourceShortName: "my-cluster",
			},
			want: "Detected a SOME_CATEGORY finding. (Resource: my-cluster)",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := generateSccDescrition(c.input.category, c.input.cveID, c.input.resourceShortName)
			if c.want != got {
				t.Fatalf("Unexpected: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestGenerateSccURL(t *testing.T) {
	type args struct {
		name         string
		gcpProjectID string
	}
	cases := []struct {
		name  string
		input args
		want  string
	}{
		{
			name: "OK",
			input: args{
				name:         "organizations/111/sources/222/findings/333",
				gcpProjectID: "my-project",
			},
			want: "https://console.cloud.google.com/security/command-center/findingsv2;name=organizations%2F111%2Fsources%2F222%2Ffindings%2F333?project=my-project",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := generateSccURL(c.input.name, c.input.gcpProjectID)
			if c.want != got {
				t.Fatalf("Unexpected: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
