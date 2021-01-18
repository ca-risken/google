package main

import (
	"fmt"
	"html/template"
	"os"
	"reflect"
	"testing"
)

var (
	unixNano       int64  = 999999999
	testProjectID  string = "test-project"
	testConfigFile string = "/tmp/config.js"
)

func TestGenerateConfig(t *testing.T) {
	testClient := &cloudSploitClient{
		cloudSploitCommand:        "echo",
		cloudSploitConfigTemplate: template.Must(template.New("TestConfig").Parse(templateConfigJs)),
	}
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "OK",
			input: "test-project",
			want:  fmt.Sprintf("/tmp/%s_%d_config.js", "test-project", unixNano),
		},
		{
			name:    "NG",
			input:   "aaa/../../../",
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := testClient.generateConfig(c.input, unixNano)
			if (c.wantErr && err == nil) || (!c.wantErr && err != nil) {
				t.Fatalf("Unexpected error: wantErr=%t, err=%+v", c.wantErr, err)
			}
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestExecCloudSploit(t *testing.T) {
	testClient := &cloudSploitClient{
		cloudSploitCommand:        "echo",
		cloudSploitConfigTemplate: template.Must(template.New("TestConfig").Parse(templateConfigJs)),
	}
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "OK",
			input: "test-project",
			want:  fmt.Sprintf("/tmp/%s_%d_result.json", "test-project", unixNano),
		},
		{
			name:    "NG",
			input:   "aaa/../../../",
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, got, err := testClient.execCloudSploit(c.input, unixNano, testConfigFile)
			if (c.wantErr && err == nil) || (!c.wantErr && err != nil) {
				t.Fatalf("Unexpected error: wantErr=%t, err=%+v", c.wantErr, err)
			}
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestRemoveTempFile(t *testing.T) {
	testClient := &cloudSploitClient{
		cloudSploitCommand:        "echo",
		cloudSploitConfigTemplate: template.Must(template.New("TestConfig").Parse(templateConfigJs)),
	}
	cases := []struct {
		name       string
		inputFile1 string
		inputFile2 string
		wantErr    bool
	}{
		{
			name:       "OK",
			inputFile1: "/tmp/input-1",
			inputFile2: "/tmp/input-2",
		},
		{
			name:       "NG No such file 1",
			inputFile1: "/no/dir/input-1",
			inputFile2: "/tmp/input-2",
			wantErr:    true,
		},
		{
			name:       "NG No such file 2",
			inputFile1: "/tmp/input-1",
			inputFile2: "/no/dir/input-2",
			wantErr:    true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f1, _ := os.Create(c.inputFile1)
			defer f1.Close()
			f2, _ := os.Create(c.inputFile2)
			defer f2.Close()

			err := testClient.removeTempFiles(c.inputFile1, c.inputFile2)
			if (c.wantErr && err == nil) || (!c.wantErr && err != nil) {
				t.Fatalf("Unexpected error: wantErr=%t, err=%+v", c.wantErr, err)
			}
		})
	}
}

func TestGetScore(t *testing.T) {
	cases := []struct {
		name  string
		input *cloudSploitFinding
		want  float32
	}{
		{
			name: "OK",
			input: &cloudSploitFinding{
				Category: "Any",
				Plugin:   "Any",
				Status:   resultOK,
			},
			want: 0.0,
		},
		{
			name: "UNKNOWN",
			input: &cloudSploitFinding{
				Category: "Any",
				Plugin:   "Any",
				Status:   resultUNKNOWN,
			},
			want: 0.1,
		},
		{
			name: "WARN",
			input: &cloudSploitFinding{
				Category: "Any",
				Plugin:   "Any",
				Status:   resultWARN,
			},
			want: 0.3,
		},
		{
			name: "FAIL IAM high",
			input: &cloudSploitFinding{
				Category: categoryIAM,
				Plugin:   "corporateEmailsOnly",
				Status:   resultFAIL,
			},
			want: 0.8,
		},
		{
			name: "FAIL IAM middle",
			input: &cloudSploitFinding{
				Category: categoryIAM,
				Plugin:   "serviceAccountAdmin",
				Status:   resultFAIL,
			},
			want: 0.6,
		},
		{
			name: "FAIL SQL htgh",
			input: &cloudSploitFinding{
				Category: categorySQL,
				Plugin:   "dbPubliclyAccessible",
				Status:   resultFAIL,
			},
			want: 0.8,
		},
		{
			name: "FAIL Storage htgh",
			input: &cloudSploitFinding{
				Category: categoryStorage,
				Plugin:   "bucketAllUsersPolicy",
				Status:   resultFAIL,
			},
			want: 0.8,
		},
		{
			name: "FAIL VPC htgh",
			input: &cloudSploitFinding{
				Category: categoryVPCNetwork,
				Plugin:   "openAllPorts",
				Status:   resultFAIL,
			},
			want: 0.8,
		},
		{
			name: "FAIL VPC middle",
			input: &cloudSploitFinding{
				Category: categoryVPCNetwork,
				Plugin:   "openKibana",
				Status:   resultFAIL,
			},
			want: 0.6,
		},
		{
			name: "FAIL Other",
			input: &cloudSploitFinding{
				Category: "Any",
				Plugin:   "Any",
				Status:   resultFAIL,
			},
			want: 0.3,
		},
		{
			name: "Status any",
			input: &cloudSploitFinding{
				Category: "Any",
				Plugin:   "Any",
				Status:   "Any",
			},
			want: 0.3,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.input.getScore()
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestSetCompliance(t *testing.T) {
	cases := []struct {
		name  string
		input *cloudSploitFinding
		want  []string
	}{
		{
			name: "OK",
			input: &cloudSploitFinding{
				Category: categoryCLB,
				Plugin:   "clbHttpsOnly",
			},
			want: []string{"hippa", "pci"},
		},
		{
			name: "Not hit tag",
			input: &cloudSploitFinding{
				Category: "Any",
				Plugin:   "Any",
			},
			want: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.input.setCompliance()
			got := c.input.Compliance
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
