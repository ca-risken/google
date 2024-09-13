package cloudsploit

import (
	"context"
	"fmt"
	"html/template"
	"os"
	"reflect"
	"testing"

	"github.com/ca-risken/common/pkg/cloudsploit"
	"github.com/ca-risken/common/pkg/logging"
)

var (
	unixNano       int64 = 999999999
	testConfigFile       = "/tmp/config.js"
)

var testClient *CloudSploitClient

func init() {
	setting, err := loadCloudsploitSetting("")
	if err != nil {
		panic(err)
	}
	testClient = &CloudSploitClient{
		cloudSploitCommand:        "echo",
		cloudSploitConfigTemplate: template.Must(template.New("TestConfig").Parse(templateConfigJs)),
		cloudsploitSetting:        setting,
		logger:                    logging.NewLogger(),
	}
}

func TestGenerateConfig(t *testing.T) {
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
			ctx := context.Background()
			got, err := testClient.generateConfig(ctx, c.input, unixNano)
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
			ctx := context.Background()
			_, got, err := testClient.execCloudSploit(ctx, c.input, unixNano, testConfigFile)
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
			want: 1.0,
		},
		{
			name: "WARN",
			input: &cloudSploitFinding{
				Category: "Any",
				Plugin:   "Any",
				Status:   resultWARN,
			},
			want: 3.0,
		},
		{
			name: "FAIL IAM high",
			input: &cloudSploitFinding{
				Category: "IAM",
				Plugin:   "corporateEmailsOnly",
				Status:   resultFAIL,
			},
			want: 8.0,
		},
		{
			name: "FAIL IAM middle",
			input: &cloudSploitFinding{
				Category: "IAM",
				Plugin:   "serviceAccountAdmin",
				Status:   resultFAIL,
			},
			want: 6.0,
		},
		{
			name: "FAIL SQL htgh",
			input: &cloudSploitFinding{
				Category: "SQL",
				Plugin:   "dbPubliclyAccessible",
				Status:   resultFAIL,
			},
			want: 8.0,
		},
		{
			name: "FAIL Storage htgh",
			input: &cloudSploitFinding{
				Category: "Storage",
				Plugin:   "bucketAllUsersPolicy",
				Status:   resultFAIL,
			},
			want: 6.0,
		},
		{
			name: "FAIL VPC htgh",
			input: &cloudSploitFinding{
				Category: "VPC Network",
				Plugin:   "openAllPorts",
				Status:   resultFAIL,
			},
			want: 8.0,
		},
		{
			name: "FAIL VPC middle",
			input: &cloudSploitFinding{
				Category: "VPC Network",
				Plugin:   "openSSH",
				Status:   resultFAIL,
			},
			want: 6.0,
		},
		{
			name: "FAIL Other",
			input: &cloudSploitFinding{
				Category: "Any",
				Plugin:   "Any",
				Status:   resultFAIL,
			},
			want: 3.0,
		},
		{
			name: "Status any",
			input: &cloudSploitFinding{
				Category: "Any",
				Plugin:   "Any",
				Status:   "Any",
			},
			want: 3.0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := testClient.getScore(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestGetRecommend(t *testing.T) {
	cases := []struct {
		name  string
		input *cloudSploitFinding
		want  *cloudsploit.PluginRecommend
	}{
		{
			name: "Exists",
			input: &cloudSploitFinding{
				Category: "CLB",
				Plugin:   "clbCDNEnabled",
			},
			want: &cloudsploit.PluginRecommend{
				Risk: cloudsploit.Ptr(`CLB CDN Enabled
- Ensures that Cloud CDN is enabled on all load balancers
- Cloud CDN increases speed and reliability as well as lowers server costs. Enabling CDN on load balancers creates a highly available system and is part of GCP best practices.`),
				Recommendation: cloudsploit.Ptr(`Enable Cloud CDN on all load balancers from the network services console.
- https://cloud.google.com/cdn/docs/quickstart`),
			},
		},
		{
			name: "Unknown",
			input: &cloudSploitFinding{
				Category: "Unknown",
				Plugin:   "Unknown",
			},
			want: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := testClient.getRecommend(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data: want=%v, got=%v", c.want, got)
			}
		})
	}
}
