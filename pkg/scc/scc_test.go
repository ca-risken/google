package scc

import (
	"reflect"
	"testing"

	sccpb "cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"github.com/ca-risken/common/pkg/logging"
)

func TestScoreSCC(t *testing.T) {
	client := NewSqsHandler(nil, nil, nil, nil, nil, false, []string{"TOXIC_COMBINATION", "THREAT"}, logging.NewLogger())
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
		{
			name: "TOXIC_COMBINATION",
			input: &sccpb.Finding{
				Severity:     sccpb.Finding_CRITICAL,
				FindingClass: sccpb.Finding_TOXIC_COMBINATION,
			},
			want: 0.1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := client.scoreSCC(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
