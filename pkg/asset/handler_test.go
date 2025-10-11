package asset

import (
	"reflect"
	"testing"

	asset "cloud.google.com/go/asset/apiv1/assetpb"
	bucketIAM "cloud.google.com/go/iam"
	iam "cloud.google.com/go/iam/apiv1/iampb"
	"cloud.google.com/go/storage"
	"github.com/ca-risken/common/pkg/dlp"
	"github.com/google/go-cmp/cmp"
)

func TestIsUserServiceAccount(t *testing.T) {
	cases := []struct {
		name  string
		input []string
		want  bool
	}{
		{
			name:  "OK",
			input: []string{"iam.googleapis.com/ServiceAccount", "//.../account@my-project.iam.gserviceaccount.com"},
			want:  true,
		},
		{
			name:  "No other type",
			input: []string{"iam.googleapis.com/NotServiceAccount", "//.../account@my-project.iam.gserviceaccount.com"},
			want:  false,
		},
		{
			name:  "No email not match",
			input: []string{"iam.googleapis.com/ServiceAccount", "//.../account@service.gserviceaccount.com"},
			want:  false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := isUserServiceAccount(c.input[0], c.input[1])
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestScoreAsset(t *testing.T) {
	cases := []struct {
		name  string
		input *assetFinding
		want  float32
	}{
		{
			name:  "OK Blank",
			input: &assetFinding{},
			want:  0.0,
		},
		{
			name: "OK Some asset",
			input: &assetFinding{
				Asset: &asset.ResourceSearchResult{
					AssetType: "some-type",
					Name:      "some-asset",
				},
			},
			want: 0.0,
		},
		{
			name: "OK IAM",
			input: &assetFinding{
				Asset: &asset.ResourceSearchResult{
					AssetType: assetTypeServiceAccount,
					Name:      "//iam.googleapis.com/projects/my-project/serviceAccounts/my-account@my-project.iam.gserviceaccount.com",
				},
				IAMPolicy: &[]string{},
			},
			want: 0.0,
		},
		{
			name: "OK Storage",
			input: &assetFinding{
				Asset: &asset.ResourceSearchResult{
					AssetType:   assetTypeBucket,
					DisplayName: "bucket-name",
				},
				BucketPolicy: &bucketIAM.Policy{},
			},
			want: 0.0,
		},
		{
			name: "Storage Public",
			input: &assetFinding{
				Asset: &asset.ResourceSearchResult{
					AssetType:   assetTypeBucket,
					DisplayName: "bucket-name",
				},
				BucketPolicy: &bucketIAM.Policy{
					InternalProto: &iam.Policy{
						Bindings: []*iam.Binding{
							{Role: "roles/storage.objectViewer", Members: []string{allUsers}},
						},
					},
				},
				BucketPublicAccessPrevention: Ptr(storage.PublicAccessPreventionUnknown),
			},
			want: 0.7,
		},
		{
			name: "Storage PublicAccessPreventionInherited",
			input: &assetFinding{
				Asset: &asset.ResourceSearchResult{
					AssetType:   assetTypeBucket,
					DisplayName: "bucket-name",
				},
				BucketPolicy: &bucketIAM.Policy{
					InternalProto: &iam.Policy{
						Bindings: []*iam.Binding{
							{Role: "roles/storage.objectViewer", Members: []string{allUsers}},
						},
					},
				},
				BucketPublicAccessPrevention: Ptr(storage.PublicAccessPreventionInherited),
			},
			want: 0.7,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scoreAsset(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestScoreAssetForIAM(t *testing.T) {
	cases := []struct {
		name  string
		input *assetFinding
		want  float32
	}{
		{
			name: "No IAM data",
			input: &assetFinding{
				Asset: &asset.ResourceSearchResult{
					AssetType: "some-type",
					Name:      "some-asset",
				},
			},
			want: 0.0,
		},
		{
			name: "OK Exists ServiceAccount 1",
			input: &assetFinding{
				Asset: &asset.ResourceSearchResult{
					AssetType: assetTypeServiceAccount,
					Name:      "//iam.googleapis.com/projects/my-project/serviceAccounts/my-account@my-project.iam.gserviceaccount.com",
				},
				HasServiceAccountKey: true,
				IAMPolicy: &[]string{
					"roles/viewer",
					"roles/some-role",
				},
			},
			want: 0.1,
		},
		{
			name: "OK Exists ServiceAccount 2",
			input: &assetFinding{
				Asset: &asset.ResourceSearchResult{
					AssetType: assetTypeServiceAccount,
					Name:      "//iam.googleapis.com/projects/my-project/serviceAccounts/my-account@my-project.iam.gserviceaccount.com",
				},
				HasServiceAccountKey: true,
				IAMPolicy:            &[]string{},
			},
			want: 0.0,
		},
		{
			name: "OK Exists Admin ServiceAccount",
			input: &assetFinding{
				Asset: &asset.ResourceSearchResult{
					AssetType: assetTypeServiceAccount,
					Name:      "//iam.googleapis.com/projects/my-project/serviceAccounts/my-account@my-project.iam.gserviceaccount.com",
				},
				HasServiceAccountKey: true,
				IAMPolicy: &[]string{
					"roles/viewer",
					roleOwner,
				},
			},
			want: 0.8,
		},
		{
			name: "OK Exists Admin ServiceAccount, But NO user keys",
			input: &assetFinding{
				Asset: &asset.ResourceSearchResult{
					AssetType: assetTypeServiceAccount,
					Name:      "//iam.googleapis.com/projects/my-project/serviceAccounts/my-account@my-project.iam.gserviceaccount.com",
				},
				HasServiceAccountKey: false,
				IAMPolicy: &[]string{
					"roles/viewer",
					roleOwner,
				},
			},
			want: 0.1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scoreAssetForIAM(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestScoreAssetForStorage(t *testing.T) {
	cases := []struct {
		name  string
		input *assetFinding
		want  float32
	}{
		{
			name:  "OK Blank",
			input: &assetFinding{},
			want:  0.0,
		},
		{
			name: "OK Not public",
			input: &assetFinding{
				Asset: &asset.ResourceSearchResult{
					AssetType:   assetTypeBucket,
					DisplayName: "bucket-name",
				},
				BucketPolicy: &bucketIAM.Policy{
					InternalProto: &iam.Policy{
						Bindings: []*iam.Binding{
							{Role: "roles/viewer", Members: []string{"specific-user"}},
						},
					},
				},
			},
			want: 0.1,
		},
		{
			name: "OK public but ReadOnly",
			input: &assetFinding{
				Asset: &asset.ResourceSearchResult{
					AssetType:   assetTypeBucket,
					DisplayName: "bucket-name",
				},
				BucketPolicy: &bucketIAM.Policy{
					InternalProto: &iam.Policy{
						Bindings: []*iam.Binding{
							{Role: "roles/viewer", Members: []string{allAuthenticatedUsers}},
							{Role: "roles/storage.objectViewer", Members: []string{allUsers}},
							{Role: "roles/storage.legacyObjectReader", Members: []string{allUsers}},
							{Role: "roles/storage.legacyBucketReader", Members: []string{allUsers}},
						},
					},
				},
			},
			want: 0.7,
		},
		{
			name: "OK public and writable",
			input: &assetFinding{
				Asset: &asset.ResourceSearchResult{
					AssetType:   assetTypeBucket,
					DisplayName: "bucket-name",
				},
				BucketPolicy: &bucketIAM.Policy{
					InternalProto: &iam.Policy{
						Bindings: []*iam.Binding{
							{Role: "roles/viewer", Members: []string{allAuthenticatedUsers}},
							{Role: "roles/storage.objectViewer", Members: []string{allUsers}},
							{Role: "roles/storage.objectCreator", Members: []string{allUsers}}, // Writable role
							{Role: "roles/storage.legacyBucketReader", Members: []string{allUsers}},
						},
					},
				},
			},
			want: 1.0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scoreAssetForStorage(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestGetAssetDescription(t *testing.T) {
	type args struct {
		asset *assetFinding
		score float32
	}
	cases := []struct {
		name  string
		input args
		want  string
	}{
		{
			name: "Type SA(high score)",
			input: args{
				asset: &assetFinding{
					Asset: &asset.ResourceSearchResult{
						AssetType:   assetTypeServiceAccount,
						DisplayName: "alice@some-project.iam.gserviceaccount.com",
					},
				},
				score: 0.8,
			},
			want: "Detected a privileged service-account that has owner(or editor) role. (name=alice@some-project.iam.gserviceaccount.com)",
		},
		{
			name: "Type SA(low score)",
			input: args{
				asset: &assetFinding{
					Asset: &asset.ResourceSearchResult{
						AssetType:   assetTypeServiceAccount,
						DisplayName: "alice@some-project.iam.gserviceaccount.com",
					},
				},
				score: 0.7,
			},
			want: "Detected GCP asset (type=ServiceAccount, name=alice@some-project.iam.gserviceaccount.com)",
		},
		{
			name: "Type bucket(high score)",
			input: args{
				asset: &assetFinding{
					Asset: &asset.ResourceSearchResult{
						AssetType:   assetTypeBucket,
						DisplayName: "bucket-name",
					},
				},
				score: 0.7,
			},
			want: "Detected public bucket. (name=bucket-name)",
		},
		{
			name: "Type bucket(low score)",
			input: args{
				asset: &assetFinding{
					Asset: &asset.ResourceSearchResult{
						AssetType:   assetTypeBucket,
						DisplayName: "bucket-name",
					},
				},
				score: 0.6,
			},
			want: "Detected GCP asset (type=Bucket, name=bucket-name)",
		},
		{
			name: "Type unsupported",
			input: args{
				asset: &assetFinding{
					Asset: &asset.ResourceSearchResult{
						AssetType:   "any-type",
						DisplayName: "any-name",
					},
				},
				score: 0.8,
			},
			want: "Detected GCP asset (type=any-type, name=any-name)",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := getAssetDescription(c.input.asset, c.input.score)
			if c.want != got {
				t.Fatalf("Unexpected data match: want=%s, got=%s", c.want, got)
			}
		})
	}
}

func TestParseFullScanFlag(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		expected bool
	}{
		{name: "true string", body: `{"full_scan":"true"}`, expected: true},
		{name: "false missing", body: `{"project_id":1}`, expected: false},
		{name: "boolean true", body: `{"full_scan":true}`, expected: true},
		{name: "numeric false", body: `{"full_scan":0}`, expected: false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := parseFullScanFlag(tt.body)
			if diff := cmp.Diff(tt.expected, got); diff != "" {
				t.Fatalf("parseFullScanFlag() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIsBucketPublic(t *testing.T) {
	publicPolicy := &bucketIAM.Policy{
		InternalProto: &iam.Policy{
			Bindings: []*iam.Binding{
				{Role: "roles/storage.objectViewer", Members: []string{allUsers}},
			},
		},
	}
	privatePolicy := &bucketIAM.Policy{
		InternalProto: &iam.Policy{
			Bindings: []*iam.Binding{
				{Role: "roles/storage.objectViewer", Members: []string{"user:test@example.com"}},
			},
		},
	}
	cases := []struct {
		name string
		in   *assetFinding
		want bool
	}{
		{name: "nil finding", in: nil, want: false},
		{name: "no policy", in: &assetFinding{}, want: false},
		{
			name: "public bucket",
			in: &assetFinding{
				BucketPolicy:                 publicPolicy,
				BucketPublicAccessPrevention: Ptr(storage.PublicAccessPreventionUnknown),
			},
			want: true,
		},
		{
			name: "private bucket",
			in: &assetFinding{
				BucketPolicy:                 privatePolicy,
				BucketPublicAccessPrevention: Ptr(storage.PublicAccessPreventionUnknown),
			},
			want: false,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := isBucketPublic(tt.in); got != tt.want {
				t.Fatalf("isBucketPublic() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasDLPScanData(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected bool
	}{
		{name: "has dlp scan data", input: `{"dlp_scan":{"resource_name":"bucket"}}`, expected: true},
		{name: "no dlp scan data", input: `{"other":"value"}`, expected: false},
		{name: "invalid json", input: `invalid-json`, expected: false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := hasDLPScanData(tt.input)
			if diff := cmp.Diff(tt.expected, got); diff != "" {
				t.Fatalf("hasDLPScanData() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseDLPScanData(t *testing.T) {
	cases := []struct {
		name        string
		input       string
		want        *dlp.ScanResult
		expectError bool
	}{
		{
			name:  "OK",
			input: `{"dlp_scan":{"resource_name":"bucket","scan_time":100}}`,
			want: &dlp.ScanResult{
				ResourceName: "bucket",
				ScanTime:     100,
			},
		},
		{
			name:        "no dlp scan data",
			input:       `{"other":"value"}`,
			expectError: true,
		},
		{
			name:        "invalid json",
			input:       `invalid`,
			expectError: true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDLPScanData(tt.input)
			if tt.expectError {
				if err == nil {
					t.Fatalf("parseDLPScanData() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDLPScanData() unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("parseDLPScanData() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Ptr[T any](v T) *T {
	return &v
}
