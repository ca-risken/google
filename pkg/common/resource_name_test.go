package common

import (
	"reflect"
	"testing"
)

func TestGetShortResourceName(t *testing.T) {
	myProject := "my-project"
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "OK Blank",
			input: "",
			want:  "my-project/unknown/",
		},
		{
			name:  "OK",
			input: "//iam.googleapis.com/projects/my-project/service/some-asset",
			want:  "my-project/service/some-asset",
		},
		{
			name:  "Unknown service",
			input: "some-asset",
			want:  "my-project/unknown/some-asset",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := GetShortResourceName(myProject, c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestGetServiceName(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "OK",
			input: "//iam.googleapis.com/projects/my-project/service/some-asset",
			want:  "service",
		},
		{
			name:  "Unknown service",
			input: "some-asset",
			want:  "unknown",
		},
		{
			name:  "Blank",
			input: "",
			want:  "unknown",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := GetServiceName(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
