package main

import (
	"reflect"
	"testing"

	"google.golang.org/genproto/googleapis/cloud/asset/v1"
	"google.golang.org/genproto/googleapis/iam/v1"
)

func TestGetShortNameFromResouceFullName(t *testing.T) {
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
			got := getShortNameFromResouceFullName(c.input)
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
			want:  0.1,
		},
		{
			name: "OK Some asset",
			input: &assetFinding{
				Asset: &asset.ResourceSearchResult{
					AssetType: "some-type",
					Name:      "some-asset",
				},
			},
			want: 0.1,
		},
		{
			name: "OK Exists ServiceAccount 1",
			input: &assetFinding{
				Asset: &asset.ResourceSearchResult{
					AssetType: assetTypeServiceAccount,
					Name:      "//iam.googleapis.com/projects/my-project/serviceAccounts/my-account@my-project.iam.gserviceaccount.com",
				},
				IAMPolicy: &asset.AnalyzeIamPolicyResponse{
					MainAnalysis: &asset.AnalyzeIamPolicyResponse_IamPolicyAnalysis{
						AnalysisResults: []*asset.IamPolicyAnalysisResult{
							{IamBinding: &iam.Binding{Role: "roles/viewer"}},
							{IamBinding: &iam.Binding{Role: "roles/some-role"}},
						},
					},
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
				IAMPolicy: &asset.AnalyzeIamPolicyResponse{},
			},
			want: 0.1,
		},
		{
			name: "OK Exists Admin ServiceAccount",
			input: &assetFinding{
				Asset: &asset.ResourceSearchResult{
					AssetType: assetTypeServiceAccount,
					Name:      "//iam.googleapis.com/projects/my-project/serviceAccounts/my-account@my-project.iam.gserviceaccount.com",
				},
				IAMPolicy: &asset.AnalyzeIamPolicyResponse{
					MainAnalysis: &asset.AnalyzeIamPolicyResponse_IamPolicyAnalysis{
						AnalysisResults: []*asset.IamPolicyAnalysisResult{
							{IamBinding: &iam.Binding{Role: "roles/viewer"}},
							{IamBinding: &iam.Binding{Role: roleOwner}}, // admin role
						},
					},
				},
			},
			want: 0.8,
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
