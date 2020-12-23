package main

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/CyberAgent/mimosa-google/pkg/common"
	"github.com/CyberAgent/mimosa-google/proto/google"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/mock"
)

const (
	length65string = "12345678901234567890123456789012345678901234567890123456789012345"
)

func TestListGoogleDataSource(t *testing.T) {
	var ctx context.Context
	now := time.Now()
	mockDB := mockGoogleRepository{}
	svc := googleService{repository: &mockDB}
	cases := []struct {
		name         string
		input        *google.ListGoogleDataSourceRequest
		want         *google.ListGoogleDataSourceResponse
		mockResponce *[]common.GoogleDataSource
		mockError    error
		wantErr      bool
	}{
		{
			name:  "OK",
			input: &google.ListGoogleDataSourceRequest{GoogleDataSourceId: 1},
			want: &google.ListGoogleDataSourceResponse{GoogleDataSource: []*google.GoogleDataSource{
				{GoogleDataSourceId: 1, Name: "one", Description: "desc", MaxScore: 1.0, CreatedAt: now.Unix(), UpdatedAt: now.Unix()},
				{GoogleDataSourceId: 2, Name: "two", Description: "desc", MaxScore: 1.0, CreatedAt: now.Unix(), UpdatedAt: now.Unix()},
			}},
			mockResponce: &[]common.GoogleDataSource{
				{GoogleDataSourceID: 1, Name: "one", Description: "desc", MaxScore: 1.0, CreatedAt: now, UpdatedAt: now},
				{GoogleDataSourceID: 2, Name: "two", Description: "desc", MaxScore: 1.0, CreatedAt: now, UpdatedAt: now},
			},
		},
		{
			name:      "OK empty",
			input:     &google.ListGoogleDataSourceRequest{Name: "not exists name"},
			want:      &google.ListGoogleDataSourceResponse{},
			mockError: gorm.ErrRecordNotFound,
		},
		{
			name:    "NG invalid param",
			input:   &google.ListGoogleDataSourceRequest{Name: length65string},
			wantErr: true,
		},
		{
			name:      "NG DB error",
			input:     &google.ListGoogleDataSourceRequest{GoogleDataSourceId: 1},
			mockError: gorm.ErrInvalidSQL,
			wantErr:   true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.mockResponce != nil || c.mockError != nil {
				mockDB.On("ListGoogleDataSource").Return(c.mockResponce, c.mockError).Once()
			}
			got, err := svc.ListGoogleDataSource(ctx, c.input)
			if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: %+v", err)
			}
			if c.wantErr && err == nil {
				t.Fatalf("Unexpected no error")
			}
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected mapping: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestListGCP(t *testing.T) {
	var ctx context.Context
	now := time.Now()
	mockDB := mockGoogleRepository{}
	svc := googleService{repository: &mockDB}
	cases := []struct {
		name         string
		input        *google.ListGCPRequest
		want         *google.ListGCPResponse
		mockResponce *[]common.GoogleGCP
		mockError    error
		wantErr      bool
	}{
		{
			name:  "OK",
			input: &google.ListGCPRequest{ProjectId: 1, GoogleDataSourceId: 1},
			want: &google.ListGCPResponse{Gcp: []*google.GCP{
				{GcpId: 1, GoogleDataSourceId: 1, Name: "one", ProjectId: 1, GcpOrganizationId: "org", GcpProjectId: "pj", Status: google.Status_OK, StatusDetail: "detail", ScanAt: now.Unix(), CreatedAt: now.Unix(), UpdatedAt: now.Unix()},
				{GcpId: 2, GoogleDataSourceId: 1, Name: "two", ProjectId: 1, GcpOrganizationId: "org", GcpProjectId: "pj", Status: google.Status_OK, StatusDetail: "detail", ScanAt: now.Unix(), CreatedAt: now.Unix(), UpdatedAt: now.Unix()},
			}},
			mockResponce: &[]common.GoogleGCP{
				{GCPID: 1, GoogleDataSourceID: 1, Name: "one", ProjectID: 1, GCPOrganizationID: "org", GCPProjectID: "pj", Status: "OK", StatusDetail: "detail", ScanAt: now, CreatedAt: now, UpdatedAt: now},
				{GCPID: 2, GoogleDataSourceID: 1, Name: "two", ProjectID: 1, GCPOrganizationID: "org", GCPProjectID: "pj", Status: "OK", StatusDetail: "detail", ScanAt: now, CreatedAt: now, UpdatedAt: now},
			},
		},
		{
			name:      "OK empty",
			input:     &google.ListGCPRequest{ProjectId: 1, GoogleDataSourceId: 1},
			want:      &google.ListGCPResponse{},
			mockError: gorm.ErrRecordNotFound,
		},
		{
			name:    "NG invalid param",
			input:   &google.ListGCPRequest{GoogleDataSourceId: 1},
			wantErr: true,
		},
		{
			name:      "NG DB error",
			input:     &google.ListGCPRequest{ProjectId: 1, GoogleDataSourceId: 1},
			mockError: gorm.ErrInvalidSQL,
			wantErr:   true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.mockResponce != nil || c.mockError != nil {
				mockDB.On("ListGCP").Return(c.mockResponce, c.mockError).Once()
			}
			got, err := svc.ListGCP(ctx, c.input)
			if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: %+v", err)
			}
			if c.wantErr && err == nil {
				t.Fatalf("Unexpected no error")
			}
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected mapping: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestGetGCP(t *testing.T) {
	var ctx context.Context
	now := time.Now()
	mockDB := mockGoogleRepository{}
	svc := googleService{repository: &mockDB}
	cases := []struct {
		name         string
		input        *google.GetGCPRequest
		want         *google.GetGCPResponse
		mockResponce *common.GoogleGCP
		mockError    error
		wantErr      bool
	}{
		{
			name:         "OK",
			input:        &google.GetGCPRequest{ProjectId: 1, GcpId: 1},
			want:         &google.GetGCPResponse{Gcp: &google.GCP{GcpId: 1, GoogleDataSourceId: 1, Name: "one", ProjectId: 1, GcpOrganizationId: "org", GcpProjectId: "pj", Status: google.Status_OK, StatusDetail: "detail", ScanAt: now.Unix(), CreatedAt: now.Unix(), UpdatedAt: now.Unix()}},
			mockResponce: &common.GoogleGCP{GCPID: 1, GoogleDataSourceID: 1, Name: "one", ProjectID: 1, GCPOrganizationID: "org", GCPProjectID: "pj", Status: "OK", StatusDetail: "detail", ScanAt: now, CreatedAt: now, UpdatedAt: now},
		},
		{
			name:      "OK empty",
			input:     &google.GetGCPRequest{ProjectId: 1, GcpId: 1},
			want:      &google.GetGCPResponse{},
			mockError: gorm.ErrRecordNotFound,
		},
		{
			name:    "NG invalid param",
			input:   &google.GetGCPRequest{ProjectId: 1},
			wantErr: true,
		},
		{
			name:      "NG DB error",
			input:     &google.GetGCPRequest{ProjectId: 1, GcpId: 1},
			mockError: gorm.ErrInvalidSQL,
			wantErr:   true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.mockResponce != nil || c.mockError != nil {
				mockDB.On("GetGCP").Return(c.mockResponce, c.mockError).Once()
			}
			got, err := svc.GetGCP(ctx, c.input)
			if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: %+v", err)
			}
			if c.wantErr && err == nil {
				t.Fatalf("Unexpected no error")
			}
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected mapping: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestPutGCP(t *testing.T) {
	var ctx context.Context
	now := time.Now()
	mockDB := mockGoogleRepository{}
	svc := googleService{repository: &mockDB}
	cases := []struct {
		name         string
		input        *google.PutGCPRequest
		want         *google.PutGCPResponse
		mockResponce *common.GoogleGCP
		mockError    error
		wantErr      bool
	}{
		{
			name: "OK",
			input: &google.PutGCPRequest{ProjectId: 1, Gcp: &google.GCPForUpsert{
				GcpId: 1, GoogleDataSourceId: 1, Name: "one", ProjectId: 1, GcpOrganizationId: "org", GcpProjectId: "pj", Status: google.Status_OK, StatusDetail: "detail", ScanAt: now.Unix()},
			},
			want: &google.PutGCPResponse{Gcp: &google.GCP{
				GcpId: 1, GoogleDataSourceId: 1, Name: "one", ProjectId: 1, GcpOrganizationId: "org", GcpProjectId: "pj", Status: google.Status_OK, StatusDetail: "detail", ScanAt: now.Unix(), CreatedAt: now.Unix(), UpdatedAt: now.Unix()},
			},
			mockResponce: &common.GoogleGCP{
				GCPID: 1, GoogleDataSourceID: 1, Name: "one", ProjectID: 1, GCPOrganizationID: "org", GCPProjectID: "pj", Status: "OK", StatusDetail: "detail", ScanAt: now, CreatedAt: now, UpdatedAt: now,
			},
		},
		{
			name:    "NG invalid param",
			input:   &google.PutGCPRequest{ProjectId: 1},
			wantErr: true,
		},
		{
			name: "NG DB error",
			input: &google.PutGCPRequest{ProjectId: 1, Gcp: &google.GCPForUpsert{
				GcpId: 1, GoogleDataSourceId: 1, Name: "one", ProjectId: 1, GcpOrganizationId: "org", GcpProjectId: "pj", Status: google.Status_OK, StatusDetail: "detail", ScanAt: now.Unix()},
			},
			mockError: gorm.ErrInvalidSQL,
			wantErr:   true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.mockResponce != nil || c.mockError != nil {
				mockDB.On("UpsertGCP").Return(c.mockResponce, c.mockError).Once()
			}
			got, err := svc.PutGCP(ctx, c.input)
			if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: %+v", err)
			}
			if c.wantErr && err == nil {
				t.Fatalf("Unexpected no error")
			}
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected mapping: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestDeleteGCP(t *testing.T) {
	var ctx context.Context
	mockDB := mockGoogleRepository{}
	svc := googleService{repository: &mockDB}
	cases := []struct {
		name      string
		input     *google.DeleteGCPRequest
		mockError error
		wantErr   bool
	}{
		{
			name:  "OK",
			input: &google.DeleteGCPRequest{ProjectId: 1, GcpId: 1},
		},
		{
			name:    "NG invalid param",
			input:   &google.DeleteGCPRequest{ProjectId: 1},
			wantErr: true,
		},
		{
			name:      "NG DB error",
			input:     &google.DeleteGCPRequest{ProjectId: 1, GcpId: 1},
			mockError: gorm.ErrInvalidSQL,
			wantErr:   true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mockDB.On("DeleteGCP").Return(c.mockError).Once()
			_, err := svc.DeleteGCP(ctx, c.input)
			if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: %+v", err)
			}
		})
	}
}

type mockGoogleRepository struct {
	mock.Mock
}

func (m *mockGoogleRepository) ListGoogleDataSource(googleDataSourceID uint32, name string) (*[]common.GoogleDataSource, error) {
	args := m.Called()
	return args.Get(0).(*[]common.GoogleDataSource), args.Error(1)
}
func (m *mockGoogleRepository) ListGCP(projectID, googleDataSourceID, gcpID uint32) (*[]common.GoogleGCP, error) {
	args := m.Called()
	return args.Get(0).(*[]common.GoogleGCP), args.Error(1)
}
func (m *mockGoogleRepository) GetGCP(projectID, gcpID uint32) (*common.GoogleGCP, error) {
	args := m.Called()
	return args.Get(0).(*common.GoogleGCP), args.Error(1)
}
func (m *mockGoogleRepository) UpsertGCP(data *google.GCPForUpsert) (*common.GoogleGCP, error) {
	args := m.Called()
	return args.Get(0).(*common.GoogleGCP), args.Error(1)
}
func (m *mockGoogleRepository) DeleteGCP(projectID uint32, gcpID uint32) error {
	args := m.Called()
	return args.Error(0)
}
