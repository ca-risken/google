package common

import (
	"reflect"
	"testing"
)

func TestCutString(t *testing.T) {
	cutChars := 10
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
			name:  "OK log text",
			input: "12345678901234567890",
			want:  "1234567890 ...",
		},
		{
			name:  "OK short text",
			input: "123",
			want:  "123",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CutString(c.input, cutChars)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
