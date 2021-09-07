package common

import (
	"time"

	"github.com/ca-risken/google/proto/google"
)

// CutString returns cutting specific `cut` characters with ` ...` suffix from `input` string.
func CutString(input string, cut int) string {
	if len(input) > cut {
		return input[:cut] + " ..." // cut long text
	}
	return input
}

// InitScanStatus return init AttachGCPDataSourceRequest data
func InitScanStatus(g *google.GCPDataSource) *google.AttachGCPDataSourceRequest {
	return &google.AttachGCPDataSourceRequest{
		ProjectId: g.ProjectId,
		GcpDataSource: &google.GCPDataSourceForUpsert{
			GcpId:              g.GcpId,
			GoogleDataSourceId: g.GoogleDataSourceId,
			ProjectId:          g.ProjectId,
			ScanAt:             time.Now().Unix(),
			Status:             google.Status_UNKNOWN, // After scan, will be updated
			StatusDetail:       "",
		},
	}
}
