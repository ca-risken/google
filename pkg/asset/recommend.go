package asset

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
