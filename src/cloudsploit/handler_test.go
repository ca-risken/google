package main

import (
	"reflect"
	"testing"
)

func TestScoreCloudSploit(t *testing.T) {
	cases := []struct {
		name  string
		input *cloudSploitFinding
		want  float32
	}{
		{
			name: "OK",
			input: &cloudSploitFinding{
				Category: "Any",
				Plugin:   "Any",
				Status:   resultOK,
			},
			want: 0.0,
		},
		{
			name: "UNKNOWN",
			input: &cloudSploitFinding{
				Category: "Any",
				Plugin:   "Any",
				Status:   resultUNKNOWN,
			},
			want: 0.1,
		},
		{
			name: "WARN",
			input: &cloudSploitFinding{
				Category: "Any",
				Plugin:   "Any",
				Status:   resultWARN,
			},
			want: 0.3,
		},
		{
			name: "FAIL IAM high",
			input: &cloudSploitFinding{
				Category: categoryIAM,
				Plugin:   "corporateEmailsOnly",
				Status:   resultFAIL,
			},
			want: 0.8,
		},
		{
			name: "FAIL IAM middle",
			input: &cloudSploitFinding{
				Category: categoryIAM,
				Plugin:   "serviceAccountAdmin",
				Status:   resultFAIL,
			},
			want: 0.6,
		},
		{
			name: "FAIL SQL htgh",
			input: &cloudSploitFinding{
				Category: categorySQL,
				Plugin:   "dbPubliclyAccessible",
				Status:   resultFAIL,
			},
			want: 0.8,
		},
		{
			name: "FAIL Storage htgh",
			input: &cloudSploitFinding{
				Category: categoryStorage,
				Plugin:   "bucketAllUsersPolicy",
				Status:   resultFAIL,
			},
			want: 0.8,
		},
		{
			name: "FAIL VPC htgh",
			input: &cloudSploitFinding{
				Category: categoryVPCNetwork,
				Plugin:   "openAllPorts",
				Status:   resultFAIL,
			},
			want: 0.8,
		},
		{
			name: "FAIL VPC middle",
			input: &cloudSploitFinding{
				Category: categoryVPCNetwork,
				Plugin:   "openKibana",
				Status:   resultFAIL,
			},
			want: 0.6,
		},
		{
			name: "FAIL Other",
			input: &cloudSploitFinding{
				Category: "Any",
				Plugin:   "Any",
				Status:   resultFAIL,
			},
			want: 0.3,
		},
		{
			name: "Status any",
			input: &cloudSploitFinding{
				Category: "Any",
				Plugin:   "Any",
				Status:   "Any",
			},
			want: 0.3,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scoreCloudSploit(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
