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
			name: "Status OK",
			input: &cloudSploitFinding{
				Category: "Any",
				Plugin:   "Any",
				Status:   "OK",
			},
			want: 0.0,
		},
		{
			name: "IAM high",
			input: &cloudSploitFinding{
				Category: categoryIAM,
				Plugin:   "corporateEmailsOnly",
				Status:   "Fail",
			},
			want: 0.8,
		},
		{
			name: "IAM middle",
			input: &cloudSploitFinding{
				Category: categoryIAM,
				Plugin:   "serviceAccountAdmin",
				Status:   "Fail",
			},
			want: 0.6,
		},
		{
			name: "SQL htgh",
			input: &cloudSploitFinding{
				Category: categorySQL,
				Plugin:   "dbPubliclyAccessible",
				Status:   "Fail",
			},
			want: 0.8,
		},
		{
			name: "Storage htgh",
			input: &cloudSploitFinding{
				Category: categoryStorage,
				Plugin:   "bucketAllUsersPolicy",
				Status:   "Fail",
			},
			want: 0.8,
		},
		{
			name: "VPC htgh",
			input: &cloudSploitFinding{
				Category: categoryVPCNetwork,
				Plugin:   "openAllPorts",
				Status:   "Fail",
			},
			want: 0.8,
		},
		{
			name: "VPC middle",
			input: &cloudSploitFinding{
				Category: categoryVPCNetwork,
				Plugin:   "openKibana",
				Status:   "Fail",
			},
			want: 0.6,
		},
		{
			name: "Other",
			input: &cloudSploitFinding{
				Category: "Any",
				Plugin:   "Any",
				Status:   "Fail",
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
