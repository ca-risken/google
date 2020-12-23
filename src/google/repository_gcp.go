package main

import (
	"time"

	"github.com/CyberAgent/mimosa-google/pkg/common"
	"github.com/CyberAgent/mimosa-google/proto/google"
	_ "github.com/go-sql-driver/mysql"
	"github.com/vikyd/zero"
)

func (c *googleRepository) ListGoogleDataSource(googleDataSourceID uint32, name string) (*[]common.GoogleDataSource, error) {
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
	if err := c.SlaveDB.Raw(query, params...).Scan(&data).Error; err != nil {
		return nil, err
	}
	return &data, nil
}

func (c *googleRepository) ListGCP(projectID, googleDataSourceID, gcpID uint32) (*[]common.GoogleGCP, error) {
	query := `select * from google_gcp where 1=1`
	var params []interface{}
	if !zero.IsZeroVal(projectID) {
		query += " and project_id = ?"
		params = append(params, projectID)
	}
	if !zero.IsZeroVal(googleDataSourceID) {
		query += " and google_data_source_id = ?"
		params = append(params, googleDataSourceID)
	}
	if !zero.IsZeroVal(gcpID) {
		query += " and gcp_id = ?"
		params = append(params, gcpID)
	}
	data := []common.GoogleGCP{}
	if err := c.SlaveDB.Raw(query, params...).Scan(&data).Error; err != nil {
		return nil, err
	}
	return &data, nil
}

const selectGetGoogleGCP = `select * from google_gcp where project_id=? and gcp_id=?`

func (c *googleRepository) GetGCP(projectID, gcpID uint32) (*common.GoogleGCP, error) {
	data := common.GoogleGCP{}
	if err := c.SlaveDB.Raw(selectGetGoogleGCP, projectID, gcpID).First(&data).Error; err != nil {
		return nil, err
	}
	return &data, nil
}

const insertGoogleGCP = `
INSERT INTO google_gcp (
  gcp_id,
  google_data_source_id,
  name,
  project_id,
  gcp_organization_id,
  gcp_project_id,
  status,
  status_detail,
  scan_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
	google_data_source_id=VALUES(google_data_source_id),
	name=VALUES(name),
	project_id=VALUES(project_id),
	gcp_organization_id=VALUES(gcp_organization_id),
	gcp_project_id=VALUES(gcp_project_id),
	status=VALUES(status),
	status_detail=VALUES(status_detail),
	scan_at=VALUES(scan_at)
`

func (c *googleRepository) UpsertGCP(data *google.GCPForUpsert) (*common.GoogleGCP, error) {
	if err := c.MasterDB.Exec(insertGoogleGCP,
		data.GcpId,
		data.GoogleDataSourceId,
		convertZeroValueToNull(data.Name),
		data.ProjectId,
		convertZeroValueToNull(data.GcpOrganizationId),
		convertZeroValueToNull(data.GcpProjectId),
		data.Status.String(),
		convertZeroValueToNull(data.StatusDetail),
		time.Unix(data.ScanAt, 0)).Error; err != nil {
		return nil, err
	}
	return c.GetGCPByUniqueIndex(data.ProjectId, data.GoogleDataSourceId, data.Name)
}

const deleteGCP = `delete from google_gcp where project_id=? and gcp_id=?`

func (c *googleRepository) DeleteGCP(projectID, gcpID uint32) error {
	if err := c.MasterDB.Exec(deleteGCP, projectID, gcpID).Error; err != nil {
		return err
	}
	return nil
}

const selectGetGCPByUniqueIndex = `select * from google_gcp where project_id=? and google_data_source_id=? and name=?`

func (c *googleRepository) GetGCPByUniqueIndex(projectID, googleDataSourceID uint32, name string) (*common.GoogleGCP, error) {
	data := common.GoogleGCP{}
	if err := c.MasterDB.Raw(selectGetGCPByUniqueIndex, projectID, googleDataSourceID, name).First(&data).Error; err != nil {
		return nil, err
	}
	return &data, nil
}
