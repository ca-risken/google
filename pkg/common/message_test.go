package common

import (
	"reflect"
	"testing"
)

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		input   *GCPQueueMessage
		wantErr bool
	}{
		{
			name:  "OK",
			input: &GCPQueueMessage{GCPID: 1, ProjectID: 1, GoogleDataSourceID: 1},
		},
		{
			name:  "OK(scan_only)",
			input: &GCPQueueMessage{GCPID: 1, ProjectID: 1, GoogleDataSourceID: 1, ScanOnly: true},
		},
		{
			name:    "NG Required(gcp_id)",
			input:   &GCPQueueMessage{ProjectID: 1, GoogleDataSourceID: 1},
			wantErr: true,
		},
		{
			name:    "NG Required(project_id)",
			input:   &GCPQueueMessage{GCPID: 1, GoogleDataSourceID: 1},
			wantErr: true,
		},
		{
			name:    "NG Required(project_id)",
			input:   &GCPQueueMessage{GCPID: 1, ProjectID: 1},
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

func TestParseMessage(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    *GCPQueueMessage
		wantErr bool
	}{
		{
			name:  "OK",
			input: `{"gcp_id":1, "project_id":1, "google_data_source_id":1}`,
			want:  &GCPQueueMessage{GCPID: 1, ProjectID: 1, GoogleDataSourceID: 1},
		},
		{
			name:  "OK(scan_only)",
			input: `{"gcp_id":1, "project_id":1, "google_data_source_id":1, "scan_only":"true"}`,
			want:  &GCPQueueMessage{GCPID: 1, ProjectID: 1, GoogleDataSourceID: 1, ScanOnly: true},
		},
		{
			name:    "NG Json parse erroro",
			input:   `{"parse...: error`,
			wantErr: true,
		},
		{
			name:    "NG Invalid mmessage(required parammeter)",
			input:   `{}`,
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseMessage(c.input)
			if err != nil && !c.wantErr {
				t.Fatalf("Unexpected error occured, wantErr=%t, err=%+v", c.wantErr, err)
			}
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpaeted response, want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
