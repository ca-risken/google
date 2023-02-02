package asset

import (
	"reflect"
	"testing"

	bucketIAM "cloud.google.com/go/iam"
	"google.golang.org/genproto/googleapis/cloud/asset/v1"
	"google.golang.org/genproto/googleapis/iam/v1"
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
			want: "The alice@some-project.iam.gserviceaccount.com has the admin role(owner or editor). Make sure it has the least permissions.",
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
			want: "ServiceAccount: alice@some-project.iam.gserviceaccount.com",
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
			want: "The bucket-name bucket allows public access. Make sure it needs to set publish settings.",
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
			want: "Bucket: bucket-name",
		},
		{
			name: "Type unsupported",
			input: args{
				asset: &assetFinding{
					Asset: &asset.ResourceSearchResult{
						AssetType:   "some-type",
						DisplayName: "some-asset",
					},
				},
				score: 0.8,
			},
			want: "GCP Cloud Asset: some-asset",
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
