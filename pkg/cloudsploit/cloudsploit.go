package cloudsploit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ca-risken/common/pkg/cloudsploit"
	"github.com/ca-risken/common/pkg/logging"
)

type cloudSploitServiceClient interface {
	run(ctx context.Context, gcpProjectID string) ([]*cloudSploitFinding, error)
	getScore(f *cloudSploitFinding) float32
	getRecommend(f *cloudSploitFinding) *cloudsploit.PluginRecommend
}

type CloudSploitClient struct {
	cloudSploitCommand             string
	cloudSploitConfigTemplate      *template.Template
	googleServiceAccountEmail      string
	googleServiceAccountPrivateKey string
	cloudsploitSetting             *cloudsploit.CloudsploitSetting
	logger                         logging.Logger
	maxMemSizeMB                   int
}

func NewCloudSploitClient(
	command,
	googleServiceAccountEmail,
	googleServiceAccountPrivateKey,
	cloudsploitSettingPath string,
	l logging.Logger,
	maxMemSizeMB int,
) (*CloudSploitClient, error) {
	setting, err := loadCloudsploitSetting(cloudsploitSettingPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load cloudsploit setting. error: %v", err)
	}

	return &CloudSploitClient{
		cloudSploitCommand:             command,
		cloudSploitConfigTemplate:      template.Must(template.New("CloudSploitConfig").Parse(templateConfigJs)),
		googleServiceAccountEmail:      googleServiceAccountEmail,
		googleServiceAccountPrivateKey: googleServiceAccountPrivateKey,
		cloudsploitSetting:             setting,
		logger:                         l,
		maxMemSizeMB:                   maxMemSizeMB,
	}, nil
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

	Category    string   `json:"category,omitempty"`
	Plugin      string   `json:"plugin,omitempty"`
	Description string   `json:"description,omitempty"`
	Resource    string   `json:"resource,omitempty"`
	Region      string   `json:"region,omitempty"`
	Status      string   `json:"status,omitempty"`
	Message     string   `json:"message,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

func (c *cloudSploitFinding) generateDataSourceID() {
	hash := sha256.Sum256([]byte(c.Category + c.Plugin + c.Description + c.Region + c.Resource))
	c.DataSourceID = hex.EncodeToString(hash[:])
}

func (c *CloudSploitClient) run(ctx context.Context, gcpProjectID string) ([]*cloudSploitFinding, error) {
	unixNano := time.Now().UnixNano()
	// Generate cloudsploit confing file
	configJs, err := c.generateConfig(ctx, gcpProjectID, unixNano)
	if err != nil {
		c.logger.Errorf(ctx, "Failed to generate config file, gcpProjectID=%s, err=%+v", gcpProjectID, err)
		return nil, err
	}

	// Exec CloudSploit
	result, resultJSON, err := c.execCloudSploit(ctx, gcpProjectID, unixNano, configJs)
	if err != nil {
		c.logger.Errorf(ctx, "Failed to exec cloudsploit, gcpProjectID=%s, err=%+v", gcpProjectID, err)
		return nil, err
	}

	// Remove temp files
	if err = c.removeTempFiles(configJs, resultJSON); err != nil {
		c.logger.Errorf(ctx, "Failed to remove temp files, gcpProjectID=%s, err=%+v", gcpProjectID, err)
		return nil, err
	}
	return result, nil
}

func (c *CloudSploitClient) generateConfig(ctx context.Context, gcpProjectID string, unixNano int64) (string, error) {
	configJs, err := os.Create(fmt.Sprintf("/tmp/%s_%d_config.js", gcpProjectID, unixNano))
	if err != nil {
		return "", err
	}
	defer configJs.Close()

	if err = c.cloudSploitConfigTemplate.Execute(configJs, gcpProjectID); err != nil {
		c.logger.Errorf(ctx, "Failed to execute confing template, gcpProjectID=%s, err=%+v", gcpProjectID, err)
		return "", err
	}
	return configJs.Name(), nil
}

const (
	resourceNotApplicable string = "N/A"
	resourceUnknown       string = "Unknown"
)

func (c *CloudSploitClient) execCloudSploit(ctx context.Context, gcpProjectID string, unixNano int64, configJs string) ([]*cloudSploitFinding, string, error) {
	filepath := fmt.Sprintf("/tmp/%s_%d_result.json", gcpProjectID, unixNano)
	if c.maxMemSizeMB > 0 {
		os.Setenv("NODE_OPTIONS", fmt.Sprintf("--max-old-space-size=%d", c.maxMemSizeMB))
	}
	resultJSON, err := os.Create(filepath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create result file, path:%s, err:%w", filepath, err)
	}
	defer resultJSON.Close()
	cmd := exec.Command(
		c.cloudSploitCommand,
		"--config", configJs,
		"--json", filepath,
		"--console", "none",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		return nil, "", fmt.Errorf("Failed exec cloudsploit. error: %+v, detail: %s", err, stderr.String())
	}

	findings, err := c.generateFindingsFromFile(ctx, resultJSON)
	if err != nil {
		return nil, "", err
	}
	return findings, filepath, nil
}

func (c *CloudSploitClient) removeTempFiles(configFilePath, resutlFilePath string) error {
	if err := os.Remove(configFilePath); err != nil {
		return err
	}
	if err := os.Remove(resutlFilePath); err != nil {
		return err
	}
	return nil
}

func (c *CloudSploitClient) generateFindingsFromFile(ctx context.Context, jsonFile *os.File) ([]*cloudSploitFinding, error) {
	buf, err := io.ReadAll(jsonFile)
	if err != nil {
		return nil, err
	}

	var findings []*cloudSploitFinding
	if len(buf) == 0 {
		c.logger.Warn(ctx, "Result file is empty")
		return findings, nil // empty
	}
	if err := json.Unmarshal(buf, &findings); err != nil {
		return nil, fmt.Errorf("failed parse result JSON. error: %w", err)
	}

	results := []*cloudSploitFinding{}
	for _, f := range findings {
		plugin := fmt.Sprintf("%s/%s", f.Category, f.Plugin)
		if c.cloudsploitSetting.IsIgnorePlugin(plugin) {
			continue
		}
		if c.cloudsploitSetting.IsSkipResourceNamePattern(plugin, f.Resource, "") {
			c.logger.Infof(ctx, "Ignore resource: plugin=%s, resource=%s", plugin, f.Resource)
			continue
		}
		if c.cloudsploitSetting.IsIgnoreMessagePattern(plugin, []string{f.Message, f.Description}) {
			c.logger.Infof(ctx, "Ignore message: plugin=%s, resource=%s, msg=%s, desc=%s", plugin, f.Resource, f.Message, f.Description)
			continue
		}

		f.generateDataSourceID()
		if strings.ToUpper(f.Resource) == resourceNotApplicable {
			f.Resource = resourceUnknown
		}
		f.Tags = c.cloudsploitSetting.SpecificPluginSetting[plugin].Tags // set tags

		results = append(results, f)
	}
	return results, nil
}

const (
	// CloudSploit Result Code: https://github.com/aquasecurity/cloudsploit/blob/2ab02ba4ffcac7ca8122f37d6b453a9679447a32/docs/writing-plugins.md#result-codes
	// Result Code Label:       https://github.com/aquasecurity/cloudsploit/blob/master/postprocess/output.js
	resultOK      = "OK"      // 0: PASS: No risks
	resultWARN    = "WARN"    // 1: WARN: The result represents a potential misconfiguration or issue but is not an immediate risk
	resultFAIL    = "FAIL"    // 2: FAIL: The result presents an immediate risk to the security of the account
	resultUNKNOWN = "UNKNOWN" // 3: UNKNOWN: The results could not be determined (API failure, wrong permissions, etc.)
	WARN_MESSAGE  = "UNKNOWN status detected. Some scans may have failed. Please take action if you don't have enough permissions."
)

func (c *CloudSploitClient) getScore(f *cloudSploitFinding) float32 {
	switch strings.ToUpper(f.Status) {
	case resultOK:
		return 0.0
	case resultUNKNOWN:
		return 1.0
	case resultWARN:
		return 3.0
	default:
		// FAIL
		plugin := fmt.Sprintf("%s/%s", f.Category, f.Plugin)
		score := c.cloudsploitSetting.DefaultScore
		if plugin, ok := c.cloudsploitSetting.SpecificPluginSetting[plugin]; ok && plugin.Score != nil {
			score = *plugin.Score
		}
		return score
	}
}

func (c *CloudSploitClient) getRecommend(f *cloudSploitFinding) *cloudsploit.PluginRecommend {
	plugin := fmt.Sprintf("%s/%s", f.Category, f.Plugin)
	return c.cloudsploitSetting.SpecificPluginSetting[plugin].Recommend
}

func unknownFindings(findings []*cloudSploitFinding) string {
	unknowns := map[string]int{}
	for _, f := range findings {
		if f.Status == resultUNKNOWN {
			unknowns[fmt.Sprintf("%s: %s", f.Category, f.Message)]++
		}
	}
	statusDetail := ""
	for k := range unknowns {
		statusDetail += fmt.Sprintf("- %s\n", k)
	}
	if statusDetail != "" {
		statusDetail = fmt.Sprintf("%s\n\n%s", WARN_MESSAGE, statusDetail)
	}
	return statusDetail
}
