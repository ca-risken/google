package scc

import (
	"reflect"
	"testing"

	sccpb "cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
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
				Severity: sccpb.Finding_CRITICAL,
			},
			want: 0.9,
		},
		{
			name: "High",
			input: &sccpb.Finding{
				Severity: sccpb.Finding_HIGH,
			},
			want: 0.6,
		},
		{
			name: "Midium",
			input: &sccpb.Finding{
				Severity: sccpb.Finding_MEDIUM,
			},
			want: 0.3,
		},
		{
			name: "Low",
			input: &sccpb.Finding{
				Severity: sccpb.Finding_LOW,
			},
			want: 0.1,
		},
		{
			name: "Serverity unknown",
			input: &sccpb.Finding{
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
