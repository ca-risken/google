package common

import (
	"time"

	"github.com/ca-risken/datasource-api/proto/google"
)

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
			SpecificVersion:    g.SpecificVersion,
		},
	}
}
