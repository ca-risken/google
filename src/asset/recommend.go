package main

import (
	"fmt"

	"github.com/ca-risken/google/pkg/common"
)

type recommend struct {
	Risk           string `json:"risk,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
}

func getRecommend(assetType string) *recommend {
	r := recommendMap[assetType]
	return &r
}

// recommendMap maps risk and recommendation details to plugins.
// key: assetType, value: recommend{}
var recommendMap = map[string]recommend{
	assetTypeBucket: {
		Risk: `Storage bucket policy
		- Ensures Storage bucket policies do not allow global write, delete, or read permission
		- If you set the bucket policy to 'allUsers' or 'allAuthenticatedUsers', anyone may be able to access your bucket.
		- This policy should be restricted only to known users or accounts.`,
		Recommendation: `Ensure that each storage bucket is configured so that no member is set to 'allUsers' or 'allAuthenticatedUsers'.
		- https://cloud.google.com/storage/docs/access-control/iam`,
	},
	assetTypeServiceAccount: {
		Risk: `Service Account Admin
		- Ensures that user managed service accounts do not have any admin, owner, or write privileges.
		- Service accounts are primarily used for API access to Google. It is recommended to not use admin access for service accounts.`,
		Recommendation: `Remove owner role('roles/owner') or editor role('roles/editor') from the service account.
		- https://cloud.google.com/iam/docs/overview`,
	},
}

type dataSourceRecommend struct{}

func (d *dataSourceRecommend) DataSource() string {
	return common.AssetDataSource
}

func (d *dataSourceRecommend) ScanFailureRisk() string {
	return fmt.Sprintf("Failed to scan %s, So you are not gathering the latest security threat information.", common.AssetDataSource)
}

func (d *dataSourceRecommend) ScanFailureRecommend() string {
	return `Please review the following items and rescan,
	- Ensure the error message of the DataSource.
	- Ensure the access rights you set for the DataSource and the reachability of the network.
	- Refer to the documentation to make sure you have not omitted any of the steps you have set up.
	- https://docs.security-hub.jp/google/overview_gcp/
	- If this does not resolve the problem, or if you suspect that the problem is server-side, please contact the system administrators.`
}
