package cloudsploit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/ca-risken/common/pkg/cloudsploit"
	"github.com/ca-risken/common/pkg/logging"
)

const (
	DEFAULT_SCAN_TIMEOUT_MINUTES             = 20
	DEFAULT_SCAN_TIMEOUT_ALL_PLUGINS_MINUTES = 90
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
	parallelScanNum                int
	scanTimeout                    time.Duration
	scanTimeoutAll                 time.Duration
}

func NewCloudSploitClient(
	command,
	googleServiceAccountEmail,
	googleServiceAccountPrivateKey,
	cloudsploitSettingPath string,
	l logging.Logger,
	maxMemSizeMB int,
	parallelScanNum int,
	scanTimeoutMinutes int,
	scanTimeoutAllMinutes int,
) (*CloudSploitClient, error) {
	setting, err := loadCloudsploitSetting(cloudsploitSettingPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load cloudsploit setting. error: %v", err)
	}

	if scanTimeoutMinutes == 0 {
		scanTimeoutMinutes = DEFAULT_SCAN_TIMEOUT_MINUTES
	}
	if scanTimeoutAllMinutes == 0 {
		scanTimeoutAllMinutes = DEFAULT_SCAN_TIMEOUT_ALL_PLUGINS_MINUTES
	}
	scanTimeout := time.Duration(scanTimeoutMinutes) * time.Minute
	scanTimeoutAll := time.Duration(scanTimeoutAllMinutes) * time.Minute

	return &CloudSploitClient{
		cloudSploitCommand:             command,
		cloudSploitConfigTemplate:      template.Must(template.New("CloudSploitConfig").Parse(templateConfigJs)),
		googleServiceAccountEmail:      googleServiceAccountEmail,
		googleServiceAccountPrivateKey: googleServiceAccountPrivateKey,
		cloudsploitSetting:             setting,
		logger:                         l,
		maxMemSizeMB:                   maxMemSizeMB,
		parallelScanNum:                parallelScanNum,
		scanTimeout:                    scanTimeout,
		scanTimeoutAll:                 scanTimeoutAll,
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
	allScanCtx, allCancel := context.WithTimeout(ctx, c.scanTimeoutAll)
	defer allCancel()
	now := time.Now().UnixNano()
	
	if c.maxMemSizeMB > 0 {
		os.Setenv("NODE_OPTIONS", fmt.Sprintf("--max-old-space-size=%d", c.maxMemSizeMB))
	}
	
	// Generate cloudsploit config file
	configJs, err := c.generateConfig(ctx, gcpProjectID, now)
	if err != nil {
		c.logger.Errorf(ctx, "Failed to generate config file, gcpProjectID=%s, err=%+v", gcpProjectID, err)
		return nil, err
	}
	defer os.Remove(configJs)

	var results []*cloudSploitFinding
	var wg sync.WaitGroup
	resultChan := make(chan []*cloudSploitFinding)
	errChan := make(chan error, 1)
	
	c.logger.Debugf(ctx, "exec parallel scan: gcpProjectID=%s, plugins=%d, parallelScanNum=%d, maxMemSizeMB=%d",
		gcpProjectID, len(c.cloudsploitSetting.SpecificPluginSetting), c.parallelScanNum, c.maxMemSizeMB)
	
	semaphore := make(chan struct{}, c.parallelScanNum) // parallel scan
	
	for plugin := range c.cloudsploitSetting.SpecificPluginSetting {
		if c.cloudsploitSetting.IsIgnorePlugin(plugin) {
			continue
		}
		split := strings.Split(plugin, "/")
		if len(split) < 2 {
			return nil, fmt.Errorf("invalid plugin format: plugin=%s", plugin)
		}
		category := split[0]
		pluginName := split[1]

		wg.Add(1)
		go func(gcpProjectID, category, pluginName string, now int64) {
			defer wg.Done()
			scanCtx, scanCancel := context.WithTimeout(allScanCtx, c.scanTimeout)
			defer scanCancel()

			select {
			case <-allScanCtx.Done():
				if allScanCtx.Err() == context.DeadlineExceeded {
					c.logger.Warnf(ctx, "scan timeout: gcpProjectID=%s, category=%s, plugin=%s, timeout=%d(min)",
						gcpProjectID, category, pluginName, int(c.scanTimeoutAll.Minutes()))
					return
				}
				errChan <- allScanCtx.Err()
				return
			case semaphore <- struct{}{}: // get semaphore
				defer func() { <-semaphore }()
			}

			c.logger.Debugf(ctx, "start scan: gcpProjectID=%s, category=%s, plugin=%s", gcpProjectID, category, pluginName)
			startUnix := time.Now().Unix()
			pluginResults, err := c.scan(scanCtx, gcpProjectID, category, pluginName, configJs, now)
			if err != nil {
				if scanCtx.Err() == context.DeadlineExceeded {
					c.logger.Warnf(ctx, "scan timeout: gcpProjectID=%s, category=%s, plugin=%s, timeout=%d(min)",
						gcpProjectID, category, pluginName, int(c.scanTimeout.Minutes()))
					return
				} else {
					errChan <- fmt.Errorf("gcpProjectID=%s, category=%s, plugin=%s, error=%w", gcpProjectID, category, pluginName, err)
					return
				}
			}
			endUnix := time.Now().Unix()
			c.logger.Debugf(ctx, "end scan: gcpProjectID=%s, category=%s, plugin=%s, time=%d(sec)", gcpProjectID, category, pluginName, endUnix-startUnix)

			select {
			case resultChan <- pluginResults:
			case <-allScanCtx.Done():
				return
			}
		}(gcpProjectID, category, pluginName, now)
	}

	// Watching wait group (non-blocking)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// Result collection loop (blocking)
	for {
		select {
		case <-done:
			// Finish all scan
			close(resultChan)
			close(errChan)
			goto COLLECTION_COMPLETE
		case err := <-errChan:
			if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
				return nil, fmt.Errorf("scan error: %w", err)
			}
		case res, ok := <-resultChan:
			if !ok {
				continue
			}
			results = append(results, res...)
		}
	}

COLLECTION_COMPLETE:
	c.logger.Debugf(ctx, "end parallel scan: gcpProjectID=%s, plugins=%d, parallelScanNum=%d, maxMemSizeMB=%d",
		gcpProjectID, len(c.cloudsploitSetting.SpecificPluginSetting), c.parallelScanNum, c.maxMemSizeMB)
	
	if len(results) > 0 {
		results = c.removeIgnoreFindings(ctx, results)
	}
	return results, nil
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

func (c *CloudSploitClient) scan(ctx context.Context, gcpProjectID, category, pluginName, configJs string, scanUnixNano int64) ([]*cloudSploitFinding, error) {
	filePath := fmt.Sprintf("/tmp/%s_%s_%s_%d.json", gcpProjectID, category, pluginName, scanUnixNano)
	if fileExists(filePath) {
		return nil, fmt.Errorf("result file already exists: file=%s", filePath)
	}
	defer os.Remove(filePath)

	cmd := exec.CommandContext(ctx, c.cloudSploitCommand,
		"--config", configJs,
		"--console", "none",
		"--plugin", pluginName,
		"--json", filePath,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed exec cloudsploit. error: %w, detail: %s", err, stderr.String())
	}

	buf, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	if len(buf) == 0 {
		c.logger.Warn(ctx, "scan output file is empty")
		return []*cloudSploitFinding{}, nil
	}

	var results []*cloudSploitFinding
	if err := json.Unmarshal(buf, &results); err != nil {
		return nil, fmt.Errorf("json parse error(scan output file): output_length=%d, err=%v", len(string(buf)), err)
	}
	return results, nil
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func (c *CloudSploitClient) removeIgnoreFindings(ctx context.Context, findings []*cloudSploitFinding) []*cloudSploitFinding {
	removedResult := []*cloudSploitFinding{}
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

		removedResult = append(removedResult, f)
	}
	return removedResult
}

const (
	resourceNotApplicable string = "N/A"
	resourceUnknown       string = "Unknown"
)

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
