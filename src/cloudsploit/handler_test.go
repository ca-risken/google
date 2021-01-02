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
				Resource: "some-resource",
				Status:   "OK",
			},
			want: 0.0,
		},
		{
			name: "Unknown resource",
			input: &cloudSploitFinding{
				Resource: resourceUnknown,
				Status:   "Fail",
			},
			want: 0.1,
		},
		{
			name: "Status Fail",
			input: &cloudSploitFinding{
				Resource: "some-resource",
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
