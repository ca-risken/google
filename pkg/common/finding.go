package common

import "github.com/ca-risken/core/proto/finding"

const ProviderGoogle = "google"

func SetGoogleProvider(f *finding.FindingForUpsert, gcpProjectID string) {
	f.Provider = ProviderGoogle
	f.ProviderTarget = gcpProjectID
}
