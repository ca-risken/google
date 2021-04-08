package google

import (
	"testing"
	"time"
)

const (
	stringLength65           = "12345678901234567890123456789012345678901234567890123456789012345"
	stringLength129          = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789=12345678901234567890123456789"
	stringLength256          = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789=123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789=12345678901234567890123456789012345678901234567890123456"
	unixtime19691231T235959  = -1
	unixtime100000101T000000 = 253402268400
)

func TestValidate_ListGoogleDataSourceRequest(t *testing.T) {
	cases := []struct {
		name    string
		input   *ListGoogleDataSourceRequest
		wantErr bool
	}{
		{
			name:  "OK",
			input: &ListGoogleDataSourceRequest{GoogleDataSourceId: 1, Name: "name"},
		},
		{
			name:  "OK empty",
			input: &ListGoogleDataSourceRequest{},
		},
		{
			name:    "NG length(name)",
			input:   &ListGoogleDataSourceRequest{GoogleDataSourceId: 1, Name: stringLength65},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.input.Validate()
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			} else if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: wantErr=%t, err=%+v", c.wantErr, err)
			}
		})
	}
}

func TestValidate_ListGCPRequest(t *testing.T) {
	cases := []struct {
		name    string
		input   *ListGCPRequest
		wantErr bool
	}{
		{
			name:  "OK",
			input: &ListGCPRequest{ProjectId: 1, GcpId: 1, GcpProjectId: "pj"},
		},
		{
			name:    "NG Required(project_id)",
			input:   &ListGCPRequest{ProjectId: 1, GcpId: 1, GcpProjectId: stringLength129},
			wantErr: true,
		},
		{
			name:    "NG Length(gcp_project_id)",
			input:   &ListGCPRequest{GcpId: 1, GcpProjectId: "pj"},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.input.Validate()
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			} else if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: wantErr=%t, err=%+v", c.wantErr, err)
			}
		})
	}
}

func TestValidate_GetGCPRequest(t *testing.T) {
	cases := []struct {
		name    string
		input   *GetGCPRequest
		wantErr bool
	}{
		{
			name:  "OK",
			input: &GetGCPRequest{ProjectId: 1, GcpId: 1},
		},
		{
			name:    "NG Required(project_id)",
			input:   &GetGCPRequest{GcpId: 1},
			wantErr: true,
		},
		{
			name:    "NG Required(gcp_id)",
			input:   &GetGCPRequest{ProjectId: 1},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.input.Validate()
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			} else if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: wantErr=%t, err=%+v", c.wantErr, err)
			}
		})
	}
}

func TestValidate_PutGCPRequest(t *testing.T) {
	cases := []struct {
		name    string
		input   *PutGCPRequest
		wantErr bool
	}{
		{
			name: "OK",
			input: &PutGCPRequest{ProjectId: 1, Gcp: &GCPForUpsert{
				Name: "name", ProjectId: 1, GcpProjectId: "1", VerificationCode: "12345678",
			}},
		},
		{
			name:    "NG No GCP param",
			input:   &PutGCPRequest{ProjectId: 1},
			wantErr: true,
		},
		{
			name: "NG Invalid project_id",
			input: &PutGCPRequest{ProjectId: 999, Gcp: &GCPForUpsert{
				Name: "name", ProjectId: 1, GcpProjectId: "1",
			}},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.input.Validate()
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			} else if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: wantErr=%t, err=%+v", c.wantErr, err)
			}
		})
	}
}

func TestValidate_DeleteGCPRequest(t *testing.T) {
	cases := []struct {
		name    string
		input   *DeleteGCPRequest
		wantErr bool
	}{
		{
			name:  "OK",
			input: &DeleteGCPRequest{ProjectId: 1, GcpId: 1},
		},
		{
			name:    "NG Required(project_id)",
			input:   &DeleteGCPRequest{GcpId: 1},
			wantErr: true,
		},
		{
			name:    "NG Required(gcp_id)",
			input:   &DeleteGCPRequest{ProjectId: 1},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.input.Validate()
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			} else if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: wantErr=%t, err=%+v", c.wantErr, err)
			}
		})
	}
}

func TestValidate_ListGCPDataSourceRequest(t *testing.T) {
	cases := []struct {
		name    string
		input   *ListGCPDataSourceRequest
		wantErr bool
	}{
		{
			name:  "OK",
			input: &ListGCPDataSourceRequest{ProjectId: 1, GcpId: 1},
		},
		{
			name:    "NG Required(project_id)",
			input:   &ListGCPDataSourceRequest{GcpId: 1},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.input.Validate()
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			} else if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: wantErr=%t, err=%+v", c.wantErr, err)
			}
		})
	}
}

func TestValidate_GetGCPDataSourceRequest(t *testing.T) {
	cases := []struct {
		name    string
		input   *GetGCPDataSourceRequest
		wantErr bool
	}{
		{
			name:  "OK",
			input: &GetGCPDataSourceRequest{ProjectId: 1, GcpId: 1, GoogleDataSourceId: 1},
		},
		{
			name:    "NG Required(project_id)",
			input:   &GetGCPDataSourceRequest{GcpId: 1, GoogleDataSourceId: 1},
			wantErr: true,
		},
		{
			name:    "NG Required(gcp_id)",
			input:   &GetGCPDataSourceRequest{ProjectId: 1, GoogleDataSourceId: 1},
			wantErr: true,
		},
		{
			name:    "NG Required(google_data_source_id)",
			input:   &GetGCPDataSourceRequest{ProjectId: 1, GcpId: 1},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.input.Validate()
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			} else if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: wantErr=%t, err=%+v", c.wantErr, err)
			}
		})
	}
}

func TestValidate_AttachGCPDataSourceRequest(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name    string
		input   *AttachGCPDataSourceRequest
		wantErr bool
	}{
		{
			name: "OK",
			input: &AttachGCPDataSourceRequest{ProjectId: 1, GcpDataSource: &GCPDataSourceForUpsert{
				GcpId: 1, GoogleDataSourceId: 1, ProjectId: 1, Status: Status_OK, StatusDetail: "detail", ScanAt: now.Unix(),
			}},
		},
		{
			name:    "NG No GcpDataSource param",
			input:   &AttachGCPDataSourceRequest{ProjectId: 1},
			wantErr: true,
		},
		{
			name: "NG Invalid project_id",
			input: &AttachGCPDataSourceRequest{ProjectId: 999, GcpDataSource: &GCPDataSourceForUpsert{
				GcpId: 1, GoogleDataSourceId: 1, ProjectId: 1, Status: Status_OK, StatusDetail: "detail", ScanAt: now.Unix(),
			}},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.input.Validate()
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			} else if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: wantErr=%t, err=%+v", c.wantErr, err)
			}
		})
	}
}

func TestValidate_DetachGCPDataSourceRequest(t *testing.T) {
	cases := []struct {
		name    string
		input   *DetachGCPDataSourceRequest
		wantErr bool
	}{
		{
			name:  "OK",
			input: &DetachGCPDataSourceRequest{ProjectId: 1, GcpId: 1, GoogleDataSourceId: 1},
		},
		{
			name:    "NG Required(project_id)",
			input:   &DetachGCPDataSourceRequest{GcpId: 1, GoogleDataSourceId: 1},
			wantErr: true,
		},
		{
			name:    "NG Required(gcp_id)",
			input:   &DetachGCPDataSourceRequest{ProjectId: 1, GoogleDataSourceId: 1},
			wantErr: true,
		},
		{
			name:    "NG Required(google_data_source_id)",
			input:   &DetachGCPDataSourceRequest{ProjectId: 1, GcpId: 1},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.input.Validate()
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			} else if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: wantErr=%t, err=%+v", c.wantErr, err)
			}
		})
	}
}

func TestValidate_InvokeScanGCPRequest(t *testing.T) {
	cases := []struct {
		name    string
		input   *InvokeScanGCPRequest
		wantErr bool
	}{
		{
			name:  "OK",
			input: &InvokeScanGCPRequest{ProjectId: 1, GcpId: 1, GoogleDataSourceId: 1},
		},
		{
			name:    "NG Required(project_id)",
			input:   &InvokeScanGCPRequest{GcpId: 1, GoogleDataSourceId: 1},
			wantErr: true,
		},
		{
			name:    "NG Required(gcp_id)",
			input:   &InvokeScanGCPRequest{ProjectId: 1, GoogleDataSourceId: 1},
			wantErr: true,
		},
		{
			name:    "NG Required(google_data_source_id)",
			input:   &InvokeScanGCPRequest{ProjectId: 1, GcpId: 1},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.input.Validate()
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			} else if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: wantErr=%t, err=%+v", c.wantErr, err)
			}
		})
	}
}

func TestValidate_GCPForUpsert(t *testing.T) {
	cases := []struct {
		name    string
		input   *GCPForUpsert
		wantErr bool
	}{
		{
			name: "OK",
			input: &GCPForUpsert{
				GcpId: 1, Name: "name", ProjectId: 1, GcpProjectId: "my-pj", VerificationCode: "12345678",
			},
		},
		{
			name: "OK minimize",
			input: &GCPForUpsert{
				Name: "name", ProjectId: 1, GcpProjectId: "my-pj", VerificationCode: "12345678",
			},
		},
		{
			name: "NG Required(name)",
			input: &GCPForUpsert{
				GcpId: 1, ProjectId: 1, GcpProjectId: "my-pj", VerificationCode: "12345678",
			},
			wantErr: true,
		},
		{
			name: "NG Length(name)",
			input: &GCPForUpsert{
				GcpId: 1, Name: stringLength65, ProjectId: 1, GcpProjectId: "my-pj", VerificationCode: "12345678",
			},
			wantErr: true,
		},
		{
			name: "NG Required(project_id)",
			input: &GCPForUpsert{
				GcpId: 1, Name: "name", GcpProjectId: "my-pj", VerificationCode: "12345678",
			},
			wantErr: true,
		},
		{
			name: "NG Length(gcp_organization_id)",
			input: &GCPForUpsert{
				GcpId: 1, Name: "name", ProjectId: 1, GcpOrganizationId: stringLength129, GcpProjectId: "my-pj", VerificationCode: "12345678",
			},
			wantErr: true,
		},
		{
			name: "NG Required(gcp_project_id)",
			input: &GCPForUpsert{
				GcpId: 1, Name: "name", ProjectId: 1, VerificationCode: "12345678",
			},
			wantErr: true,
		},
		{
			name: "NG Length(gcp_project_id)",
			input: &GCPForUpsert{
				GcpId: 1, Name: "name", ProjectId: 1, GcpProjectId: stringLength129, VerificationCode: "12345678",
			},
			wantErr: true,
		},
		{
			name: "NG Required(verification_code)",
			input: &GCPForUpsert{
				GcpId: 1, Name: "name", ProjectId: 1, GcpProjectId: "my-pj",
			},
			wantErr: true,
		},
		{
			name: "NG MinLength(verification_code)",
			input: &GCPForUpsert{
				GcpId: 1, Name: "name", ProjectId: 1, GcpProjectId: stringLength129, VerificationCode: "1234567",
			},
			wantErr: true,
		},
		{
			name: "NG MaxLength(verification_code)",
			input: &GCPForUpsert{
				GcpId: 1, Name: "name", ProjectId: 1, GcpProjectId: stringLength129, VerificationCode: stringLength256,
			},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.input.Validate()
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			} else if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: wantErr=%t, err=%+v", c.wantErr, err)
			}
		})
	}
}

func TestValidate_GCPDataSourceForUpsert(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name    string
		input   *GCPDataSourceForUpsert
		wantErr bool
	}{
		{
			name: "OK",
			input: &GCPDataSourceForUpsert{
				GoogleDataSourceId: 1, ProjectId: 1, Status: Status_OK, StatusDetail: "detail", ScanAt: now.Unix(),
			},
		},
		{
			name: "OK minimize",
			input: &GCPDataSourceForUpsert{
				GoogleDataSourceId: 1, ProjectId: 1,
			},
		},
		{
			name: "NG Required(google_data_source_id)",
			input: &GCPDataSourceForUpsert{
				ProjectId: 1, Status: Status_OK, StatusDetail: "detail", ScanAt: now.Unix(),
			},
			wantErr: true,
		},
		{
			name: "NG Required(project_id)",
			input: &GCPDataSourceForUpsert{
				GoogleDataSourceId: 1, Status: Status_OK, StatusDetail: "detail", ScanAt: now.Unix(),
			},
			wantErr: true,
		},
		{
			name: "NG Length(status_detail)",
			input: &GCPDataSourceForUpsert{
				GoogleDataSourceId: 1, ProjectId: 1, Status: Status_OK, StatusDetail: stringLength256, ScanAt: now.Unix(),
			},
			wantErr: true,
		},
		{
			name: "NG Min(scan_at)",
			input: &GCPDataSourceForUpsert{
				GoogleDataSourceId: 1, ProjectId: 1, Status: Status_OK, StatusDetail: "detail", ScanAt: unixtime19691231T235959,
			},
			wantErr: true,
		},
		{
			name: "NG Max(scan_at)",
			input: &GCPDataSourceForUpsert{
				GoogleDataSourceId: 1, ProjectId: 1, Status: Status_OK, StatusDetail: "detail", ScanAt: unixtime100000101T000000,
			},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.input.Validate()
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			} else if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: wantErr=%t, err=%+v", c.wantErr, err)
			}
		})
	}
}
