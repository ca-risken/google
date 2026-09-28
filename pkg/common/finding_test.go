package common

import (
	"testing"

	"github.com/ca-risken/core/proto/finding"
)

func TestSetGoogleProvider(t *testing.T) {
	f := &finding.FindingForUpsert{}

	SetGoogleProvider(f, "gcp-project-id")

	if f.Provider != ProviderGoogle {
		t.Errorf("Provider = %q, want %q", f.Provider, ProviderGoogle)
	}
	if f.ProviderTarget != "gcp-project-id" {
		t.Errorf("ProviderTarget = %q, want %q", f.ProviderTarget, "gcp-project-id")
	}
}
