package scc

import (
	"reflect"
	"testing"

	sccpb "google.golang.org/genproto/googleapis/cloud/securitycenter/v1"
)

func TestScoreSCC(t *testing.T) {
	cases := []struct {
		name  string
		input *sccpb.Finding
		want  float32
	}{
		{
			name: "Critical",
			input: &sccpb.Finding{
				State:    sccpb.Finding_ACTIVE,
				Severity: sccpb.Finding_CRITICAL,
			},
			want: 0.9,
		},
		{
			name: "High",
			input: &sccpb.Finding{
				State:    sccpb.Finding_ACTIVE,
				Severity: sccpb.Finding_HIGH,
			},
			want: 0.6,
		},
		{
			name: "Midium",
			input: &sccpb.Finding{
				State:    sccpb.Finding_ACTIVE,
				Severity: sccpb.Finding_MEDIUM,
			},
			want: 0.3,
		},
		{
			name: "Low",
			input: &sccpb.Finding{
				State:    sccpb.Finding_ACTIVE,
				Severity: sccpb.Finding_LOW,
			},
			want: 0.1,
		},
		{
			name: "State inactive",
			input: &sccpb.Finding{
				State:    sccpb.Finding_INACTIVE,
				Severity: sccpb.Finding_LOW,
			},
			want: 0.1,
		},
		{
			name: "Serverity unknown",
			input: &sccpb.Finding{
				State:    sccpb.Finding_ACTIVE,
				Severity: sccpb.Finding_SEVERITY_UNSPECIFIED,
			},
			want: 0.0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scoreSCC(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
