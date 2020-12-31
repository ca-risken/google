package common

import (
	"reflect"
	"testing"
)

func TestGetShortName(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "OK Blank",
			input: "",
			want:  "",
		},
		{
			name:  "OK some-asset",
			input: "//iam.googleapis.com/projects/my-project/service/some-asset",
			want:  "some-asset",
		},
		{
			name:  "OK some-asset 2",
			input: "some-asset",
			want:  "some-asset",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := GetShortName(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
