package asset

import (
	"reflect"
	"testing"
)

func TestGetRecommend(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  *recommend
	}{
		{
			name:  "Exists",
			input: "storage.googleapis.com/Bucket",
			want: &recommend{
				Risk: `Storage bucket policy
		- Ensures Storage bucket policies do not allow global write, delete, or read permission
		- If you set the bucket policy to 'allUsers' or 'allAuthenticatedUsers', anyone may be able to access your bucket.
		- This policy should be restricted only to known users or accounts.`,
				Recommendation: `Ensure that each storage bucket is configured so that no member is set to 'allUsers' or 'allAuthenticatedUsers'.
		- https://cloud.google.com/storage/docs/access-control/iam`,
			},
		},
		{
			name:  "Unknown",
			input: "unknown",
			want: &recommend{
				Risk:           "",
				Recommendation: "",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := getRecommend(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data: want=%v, got=%v", c.want, got)
			}
		})
	}
}
