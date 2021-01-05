package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
)

type cloudSploitServiceClient interface {
	run(ctx context.Context, gcpProjectID string) (*[]cloudSploitFinding, error)
}

type cloudSploitClient struct {
	cloudSploitCommand             string
	cloudSploitConfigTemplate      *template.Template
	googleServiceAccountEmail      string
	googleServiceAccountPrivateKey string
}

type cloudSploitConf struct {
	CloudSploitCommand             string `required:"true" split_words:"true"`
	GoogleServiceAccountEmail      string `required:"true" split_words:"true"`
	GoogleServiceAccountPrivateKey string `required:"true" split_words:"true"`
}

func newCloudSploitClient() cloudSploitServiceClient {
	var conf cloudSploitConf
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatalf("Could not read confg. err: %+v", err)
	}
	return &cloudSploitClient{
		cloudSploitCommand:             conf.CloudSploitCommand,
		cloudSploitConfigTemplate:      template.Must(template.New("CloudSploitConfig").Parse(templateConfigJs)),
		googleServiceAccountEmail:      conf.GoogleServiceAccountEmail,
		googleServiceAccountPrivateKey: conf.GoogleServiceAccountPrivateKey,
	}
}

const templateConfigJs string = `
module.exports = {
	credentials: {
		google: {
			project: '{{.}}',
			client_email: process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL || '',
			private_key: process.env.GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY || '',
		},
		aws: {},
		azure: {},
		oracle: {},
		github: {},
	}
};
`

type cloudSploitFinding struct {
	DataSourceID string `json:"data_source_id"`

	Category    string `json:"category,omitempty"`
	Plugin      string `json:"plugin,omitempty"`
	Description string `json:"description,omitempty"`
	Resource    string `json:"resource,omitempty"`
	Region      string `json:"region,omitempty"`
	Status      string `json:"status,omitempty"`
	Message     string `json:"message,omitempty"`
}

func (c *cloudSploitFinding) generateDataSourceID() {
	hash := sha256.Sum256([]byte(c.Category + c.Plugin + c.Description + c.Region + c.Resource + c.Message))
	c.DataSourceID = hex.EncodeToString(hash[:])
}

func (g *cloudSploitClient) run(ctx context.Context, gcpProjectID string) (*[]cloudSploitFinding, error) {
	unixNano := time.Now().UnixNano()
	// Generate cloudsploit confing file
	configJs, err := g.generateConfig(gcpProjectID, unixNano)
	if err != nil {
		appLogger.Errorf("Failed to generate config file, gcpProjectID=%s, err=%+v", gcpProjectID, err)
		return nil, err
	}

	// Exec CloudSploit
	result, resultJSON, err := g.execCloudSploit(gcpProjectID, unixNano, configJs)
	if err != nil {
		appLogger.Errorf("Failed to exec cloudsploit, gcpProjectID=%s, err=%+v", gcpProjectID, err)
		return nil, err
	}

	// Remove temp files
	if err = g.removeTempFiles(configJs, resultJSON); err != nil {
		appLogger.Errorf("Failed to remove temp files, gcpProjectID=%s, err=%+v", gcpProjectID, err)
		return nil, err
	}
	return result, nil
}

func (g *cloudSploitClient) generateConfig(gcpProjectID string, unixNano int64) (string, error) {
	configJs, err := os.Create(fmt.Sprintf("/tmp/%s_%d_config.js", gcpProjectID, unixNano))
	if err != nil {
		return "", err
	}
	defer configJs.Close()

	if err = g.cloudSploitConfigTemplate.Execute(configJs, gcpProjectID); err != nil {
		appLogger.Errorf("Failed to execute confing template, gcpProjectID=%s, err=%+v", gcpProjectID, err)
		return "", err
	}
	return configJs.Name(), nil
}

const (
	resourceNotApplicable string = "N/A"
	resourceUnknown       string = "Unknown"
)

func (g *cloudSploitClient) execCloudSploit(gcpProjectID string, unixNano int64, configJs string) (*[]cloudSploitFinding, string, error) {
	resultJSON, err := os.Create(fmt.Sprintf("/tmp/%s_%d_result.json", gcpProjectID, unixNano))
	if err != nil {
		return nil, "", err
	}
	defer resultJSON.Close()
	out, err := exec.Command(g.cloudSploitCommand,
		"--config", configJs,
		"--json", resultJSON.Name(),
		"--console", "text",
		// "--ignore-ok",
	).Output()
	appLogger.Debug(string(out))
	if err != nil {
		appLogger.Error(string(out))
		return nil, "", err
	}

	buf, err := ioutil.ReadAll(resultJSON)
	if err != nil {
		return nil, "", err
	}
	var findings []cloudSploitFinding
	if len(buf) == 0 {
		return &findings, resultJSON.Name(), nil // empty
	}
	if err := json.Unmarshal(buf, &findings); err != nil {
		return nil, "", err
	}
	for idx := range findings {
		if strings.ToUpper(findings[idx].Resource) == resourceNotApplicable {
			findings[idx].Resource = resourceUnknown
		}
		findings[idx].generateDataSourceID()
	}
	return &findings, resultJSON.Name(), nil
}

func (g *cloudSploitClient) removeTempFiles(configFilePath, resutlFilePath string) error {
	if err := os.Remove(configFilePath); err != nil {
		return err
	}
	if err := os.Remove(resutlFilePath); err != nil {
		return err
	}
	return nil
}