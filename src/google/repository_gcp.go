package main

import (
	"time"

	"github.com/CyberAgent/mimosa-google/pkg/common"
	"github.com/CyberAgent/mimosa-google/proto/google"
	"github.com/vikyd/zero"
)

func (g *googleRepository) ListGoogleDataSource(googleDataSourceID uint32, name string) (*[]common.GoogleDataSource, error) {
	query := `select * from google_data_source where 1=1`
	var params []interface{}
	if !zero.IsZeroVal(googleDataSourceID) {
		query += " and google_data_source_id = ?"
		params = append(params, googleDataSourceID)
	}
	if !zero.IsZeroVal(name) {
		query += " and name = ?"
		params = append(params, name)
	}
	data := []common.GoogleDataSource{}
	if err := g.SlaveDB.Raw(query, params...).Scan(&data).Error; err != nil {
		return nil, err
	}
	return &data, nil
}

const selectGetGoogleDataSource string = "select * from google_data_source where google_data_source_id=?"

func (g *googleRepository) GetGoogleDataSource(googleDataSourceID uint32) (*common.GCP, error) {
	data := common.GCP{}
	if err := g.SlaveDB.Raw(selectGetGoogleDataSource, googleDataSourceID).First(&data).Error; err != nil {
		return nil, err
	}
	return &data, nil
}

func (g *googleRepository) ListGCP(projectID, gcpID uint32, gcpProjectID string) (*[]common.GCP, error) {
	query := `select * from gcp where 1=1`
	var params []interface{}
	if !zero.IsZeroVal(projectID) {
		query += " and project_id = ?"
		params = append(params, projectID)
	}
	if !zero.IsZeroVal(gcpID) {
		query += " and gcp_id = ?"
		params = append(params, gcpID)
	}
	if !zero.IsZeroVal(gcpProjectID) {
		query += " and gcp_project_id = ?"
		params = append(params, gcpProjectID)
	}
	data := []common.GCP{}
	if err := g.SlaveDB.Raw(query, params...).Scan(&data).Error; err != nil {
		return nil, err
	}
	return &data, nil
}

const selectGetGCP string = `select * from gcp where project_id=? and gcp_id=?`

func (g *googleRepository) GetGCP(projectID, gcpID uint32) (*common.GCP, error) {
	data := common.GCP{}
	if err := g.SlaveDB.Raw(selectGetGCP, projectID, gcpID).First(&data).Error; err != nil {
		return nil, err
	}
	return &data, nil
}

const insertUpsertGCP = `
INSERT INTO gcp (
  gcp_id,
  name,
  project_id,
  gcp_organization_id,
  gcp_project_id,
  verification_code
)
VALUES (?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
  name=VALUES(name),
  project_id=VALUES(project_id),
  gcp_organization_id=VALUES(gcp_organization_id),
  gcp_project_id=VALUES(gcp_project_id),
  verification_code=VALUES(verification_code)
`

func (g *googleRepository) UpsertGCP(gcp *google.GCPForUpsert) (*common.GCP, error) {
	if err := g.MasterDB.Exec(insertUpsertGCP,
		gcp.GcpId,
		convertZeroValueToNull(gcp.Name),
		gcp.ProjectId,
		convertZeroValueToNull(gcp.GcpOrganizationId),
		gcp.GcpProjectId,
		gcp.VerificationCode,
	).Error; err != nil {
		return nil, err
	}
	return g.GetGCPByUniqueIndex(gcp.ProjectId, gcp.GcpProjectId)
}

const selectGetGCPByUniqueIndex string = `select * from gcp where project_id=? and gcp_project_id=?`

func (g *googleRepository) GetGCPByUniqueIndex(projectID uint32, gcpProjectID string) (*common.GCP, error) {
	data := common.GCP{}
	if err := g.MasterDB.Raw(selectGetGCPByUniqueIndex, projectID, gcpProjectID).First(&data).Error; err != nil {
		return nil, err
	}
	return &data, nil
}

const deleteGCP string = `delete from gcp where project_id=? and gcp_id=?`

func (g *googleRepository) DeleteGCP(projectID, gcpID uint32) error {
	if err := g.MasterDB.Exec(deleteGCP, projectID, gcpID).Error; err != nil {
		return err
	}
	return nil
}

type gcpDataSource struct {
	GCPID              uint32 `gorm:"primary_key column:gcp_id"`
	GoogleDataSourceID uint32 `gorm:"primary_key"`
	ProjectID          uint32
	Status             string
	StatusDetail       string
	ScanAt             time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
	Name               string  // google_data_source.name
	Description        string  // google_data_source.description
	MaxScore           float32 // google_data_source.max_score
	GCPOrganizationID  string  // gcp.gcp_organization_id
	GCPProjectID       string  // gcp.gcp_project_id
}

func (g *googleRepository) ListGCPDataSource(projectID, gcpID uint32) (*[]gcpDataSource, error) {
	query := `
select
  gds.*, google.name, google.max_score, google.description, gcp.gcp_organization_id, gcp.gcp_project_id
from
  gcp_data_source gds
  inner join google_data_source google using(google_data_source_id)
  inner join gcp using(gcp_id, project_id)
where
	1=1
`
	var params []interface{}
	if !zero.IsZeroVal(projectID) {
		query += " and gds.project_id = ?"
		params = append(params, projectID)
	}
	if !zero.IsZeroVal(gcpID) {
		query += " and gds.gcp_id = ?"
		params = append(params, gcpID)
	}
	data := []gcpDataSource{}
	if err := g.SlaveDB.Raw(query, params...).Scan(&data).Error; err != nil {
		return nil, err
	}
	return &data, nil
}

const selectGetGCPDataSource string = `
select
  gds.*, google.name, google.max_score, google.description, gcp.gcp_organization_id, gcp.gcp_project_id
from
  gcp_data_source gds
  inner join google_data_source google using(google_data_source_id)
  inner join gcp using(gcp_id, project_id)
where
	gds.project_id=? and gds.gcp_id=? and gds.google_data_source_id=?
`

func (g *googleRepository) GetGCPDataSource(projectID, gcpID, googleDataSourceID uint32) (*gcpDataSource, error) {
	data := gcpDataSource{}
	if err := g.MasterDB.Raw(selectGetGCPDataSource, projectID, gcpID, googleDataSourceID).Scan(&data).Error; err != nil {
		return nil, err
	}
	return &data, nil
}

const insertUpsertGCPDataSource string = `
INSERT INTO gcp_data_source (
  gcp_id,
  google_data_source_id,
  project_id,
  status,
  status_detail,
  scan_at
)
VALUES (?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
  project_id=VALUES(project_id),
  status=VALUES(status),
  status_detail=VALUES(status_detail),
  scan_at=VALUES(scan_at)
`

func (g *googleRepository) UpsertGCPDataSource(gcpDataSource *google.GCPDataSourceForUpsert) (*gcpDataSource, error) {
	// Check master table exists
	if _, err := g.GetGoogleDataSource(gcpDataSource.GoogleDataSourceId); err != nil {
		appLogger.Errorf("Not exists google_data_source or DB error: google_data_source_id=%d", gcpDataSource.GoogleDataSourceId)
		return nil, err
	}
	if _, err := g.GetGCP(gcpDataSource.ProjectId, gcpDataSource.GcpId); err != nil {
		appLogger.Errorf("Not exists gcp or DB error: gcp_id=%d", gcpDataSource.GcpId)
		return nil, err
	}

	// Upsert
	if err := g.MasterDB.Exec(insertUpsertGCPDataSource,
		gcpDataSource.GcpId,
		gcpDataSource.GoogleDataSourceId,
		gcpDataSource.ProjectId,
		gcpDataSource.Status.String(),
		convertZeroValueToNull(gcpDataSource.StatusDetail),
		time.Unix(gcpDataSource.ScanAt, 0),
	).Error; err != nil {
		return nil, err
	}
	return g.GetGCPDataSource(gcpDataSource.ProjectId, gcpDataSource.GcpId, gcpDataSource.GoogleDataSourceId)
}

const deleteGCPDataSource string = `delete from gcp_data_source where project_id=? and gcp_id=? and google_data_source_id=?`

func (g *googleRepository) DeleteGCPDataSource(projectID, gcpID, googleDataSourceID uint32) error {
	if err := g.MasterDB.Exec(deleteGCPDataSource, projectID, gcpID, googleDataSourceID).Error; err != nil {
		return err
	}
	return nil
}
