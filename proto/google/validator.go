package google

import (
	"errors"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

// Validate ListGoogleDataSourceRequest
func (l *ListGoogleDataSourceRequest) Validate() error {
	return validation.ValidateStruct(l,
		validation.Field(&l.Name, validation.Length(0, 64)),
	)
}

// Validate ListGCPRequest
func (l *ListGCPRequest) Validate() error {
	return validation.ValidateStruct(l,
		validation.Field(&l.ProjectId, validation.Required),
	)
}

// Validate GetGCPRequest
func (g *GetGCPRequest) Validate() error {
	return validation.ValidateStruct(g,
		validation.Field(&g.ProjectId, validation.Required),
		validation.Field(&g.GcpId, validation.Required),
	)
}

// Validate PutGitleaksRequest
func (p *PutGCPRequest) Validate() error {
	if p.Gcp == nil {
		return errors.New("Required GCP")
	}
	if err := validation.ValidateStruct(p,
		validation.Field(&p.ProjectId, validation.Required, validation.In(p.Gcp.ProjectId)),
	); err != nil {
		return err
	}
	return p.Gcp.Validate()
}

// Validate DeleteGitleaksRequest
func (d *DeleteGCPRequest) Validate() error {
	return validation.ValidateStruct(d,
		validation.Field(&d.ProjectId, validation.Required),
		validation.Field(&d.GcpId, validation.Required),
	)
}

// Validate InvokeScanRequest
func (i *InvokeScanGCPRequest) Validate() error {
	return validation.ValidateStruct(i,
		validation.Field(&i.ProjectId, validation.Required),
		validation.Field(&i.GcpId, validation.Required),
	)
}

/**
 * Entity
**/

// Validate GCPForUpsert
func (g *GCPForUpsert) Validate() error {
	return validation.ValidateStruct(g,
		validation.Field(&g.GoogleDataSourceId, validation.Required),
		validation.Field(&g.Name, validation.Required, validation.Length(0, 64)),
		validation.Field(&g.ProjectId, validation.Required),
		validation.Field(&g.GcpOrganizationId, validation.Length(0, 128)),
		validation.Field(&g.GcpProjectId, validation.Required, validation.Length(0, 128)),
		validation.Field(&g.StatusDetail, validation.Length(0, 255)),
		validation.Field(&g.ScanAt, validation.Min(0), validation.Max(253402268399)), //  1970-01-01T00:00:00 ~ 9999-12-31T23:59:59
	)
}
