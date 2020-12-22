package common

import "time"

// GoogleDataSource entity
type GoogleDataSource struct {
	GoogleDataSourceID uint32 `gorm:"primary_key"`
	Name               string
	Description        string
	MaxScore           float32
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// GoogleGCP entity
type GoogleGCP struct {
	GCPID              uint32 `gorm:"primary_key column:gcp_id"`
	GoogleDataSourceID uint32
	Name               string
	ProjectID          uint32
	GCPOrganizationID  string `gorm:"column:gcp_organization_id"`
	GCPProjectID       string `gorm:"column:gcp_project_id"`
	Status             string
	StatusDetail       string
	ScanAt             time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
}
