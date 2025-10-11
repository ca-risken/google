package asset

import (
	"context"
	"testing"
	"time"

	"github.com/ca-risken/common/pkg/dlp"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/google/go-cmp/cmp"
)

func TestSanitizeObjectPath(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "安全な値に正規化",
			input:    `dir/../../secret:info?.txt`,
			expected: "dir/_/_/secret_info_.txt",
		},
		{
			name:     "変更なし",
			input:    "folder/file.txt",
			expected: "folder/file.txt",
		},
	}

	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := sanitizeObjectPath(tt.input)
			if diff := cmp.Diff(tt.expected, got); diff != "" {
				t.Fatalf("sanitizeObjectPath() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFilterCandidatesWithCache(t *testing.T) {
	logger := logging.NewLogger()
	client := &assetClient{logger: logger}

	now := time.Unix(1_700_000_000, 0)
	before := now.Add(-time.Hour)
	after := now.Add(time.Hour)

	prev := &dlp.ScanResult{
		ResourceName: "bucket",
		ScanTime:     now.Unix(),
		Findings: []dlp.Finding{
			{FilePath: "bucket/object-before"},
		},
	}

	candidates := []bucketFileCandidate{
		{BucketName: "bucket", ObjectName: "object-before", Updated: &before},
		{BucketName: "bucket", ObjectName: "object-after", Updated: &after},
		{BucketName: "bucket", ObjectName: "object-unknown"},
	}

	wantToScan := []bucketFileCandidate{
		{BucketName: "bucket", ObjectName: "object-after", Updated: &after},
		{BucketName: "bucket", ObjectName: "object-unknown"},
	}
	wantCached := []dlp.Finding{
		{FilePath: "bucket/object-before"},
	}

	ctx := context.Background()
	gotToScan, gotCached := client.filterCandidatesWithCache(ctx, "bucket", candidates, prev)

	if diff := cmp.Diff(wantToScan, gotToScan, cmp.AllowUnexported(bucketFileCandidate{})); diff != "" {
		t.Fatalf("filterCandidatesWithCache() targets mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(wantCached, gotCached); diff != "" {
		t.Fatalf("filterCandidatesWithCache() cached mismatch (-want +got):\n%s", diff)
	}
}
