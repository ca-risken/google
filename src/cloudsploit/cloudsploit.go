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

	"github.com/gassara-kys/envconfig"
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
	CloudSploitCommand             string `required:"true" split_words:"true" default:"cloudsploit-scan"`
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

const (
	// CloudSploit Category
	categoryCLB               string = "CLB"
	categoryCompute           string = "Compute"
	categoryCryptographicKeys string = "Cryptographic Keys"
	categoryIAM               string = "IAM"
	categoryKubernetes        string = "Kubernetes"
	categoryLogging           string = "Logging"
	categorySQL               string = "SQL"
	categoryStorage           string = "Storage"
	categoryVPCNetwork        string = "VPC Network"

	// CloudSploit Result Code: https://github.com/aquasecurity/cloudsploit/blob/2ab02ba4ffcac7ca8122f37d6b453a9679447a32/docs/writing-plugins.md#result-codes
	// Result Code Label:       https://github.com/aquasecurity/cloudsploit/blob/master/postprocess/output.js
	resultOK      string = "OK"      // 0: PASS: No risks
	resultWARN    string = "WARN"    // 1: WARN: The result represents a potential misconfiguration or issue but is not an immediate risk
	resultFAIL    string = "FAIL"    // 2: FAIL: The result presents an immediate risk to the security of the account
	resultUNKNOWN string = "UNKNOWN" // 3: UNKNOWN: The results could not be determined (API failure, wrong permissions, etc.)
)

// pluginTagMap (key: `{Categor}/{Plugin}`, value: tag)
var pluginTagMap = map[string][]string{
	categoryCLB + "/clbHttpsOnly":                  {"hippa", "pci"},       // CLB
	categoryCLB + "/clbNoInstances":                {"cost"},               // CLB
	categoryCompute + "/autoscaleEnabled":          {"reliability"},        // GCE
	categoryCompute + "/csekEncryptionEnabled":     {"hippa", "pci"},       // GCE
	categoryCompute + "/instanceLeastPrivilege":    {"pci"},                // GCE
	categoryCompute + "/instanceMaxCount":          {"reliability"},        // GCE
	categoryCompute + "/instancesMultiAz":          {"reliability"},        // GCE
	categoryCompute + "/osLoginEnabled":            {"pci"},                // GCE
	categoryCryptographicKeys + "/keyRotation":     {"hipaa", "pci"},       // KMS
	categoryIAM + "/serviceAccountKeyRotation":     {"hipaa", "pci"},       // IAM
	categoryIAM + "/serviceLimits":                 {"reliability"},        // IAM
	categoryKubernetes + "/autoNodeRepairEnabled":  {"reliability"},        // GKE
	categoryKubernetes + "/loggingEnabled":         {"hipaa"},              // GKE
	categoryLogging + "/auditConfigurationLogging": {"hipaa", "pci"},       // Logging
	categoryLogging + "/customRoleLogging":         {"hipaa"},              // Logging
	categoryLogging + "/projectOwnershipLogging":   {"hipaa", "pci"},       // Logging
	categoryLogging + "/sqlConfigurationLogging":   {"hipaa"},              // Logging
	categoryLogging + "/storagePermissionsLogging": {"hipaa", "pci"},       // Logging
	categoryLogging + "/vpcFirewallRuleLogging":    {"hipaa"},              // Logging
	categoryLogging + "/vpcNetworkLogging":         {"hipaa", "pci"},       // Logging
	categoryLogging + "/vpcNetworkRouteLogging":    {"hipaa"},              // Logging
	categorySQL + "/dbAutomatedBackups":            {"reliability"},        // CloudSQL
	categorySQL + "/dbMultiAz":                     {"reliability"},        // CloudSQL
	categorySQL + "/dbPubliclyAccessible":          {"hipaa", "pci"},       // CloudSQL
	categorySQL + "/dbRestorable":                  {"pci", "reliability"}, // CloudSQL
	categorySQL + "/dbSSLEnabled":                  {"hipaa", "pci"},       // CloudSQL
	categoryStorage + "/bucketLogging":             {"hipaa"},              // GCS
	categoryStorage + "/bucketVersioning":          {"reliability"},        // GCS
	categoryVPCNetwork + "/defaultVpcInUse":        {"pci"},                // VPC
	categoryVPCNetwork + "/excessiveFirewallRules": {"pci"},                // VPC
	categoryVPCNetwork + "/flowLogsEnabled":        {"hipaa", "pci"},       // VPC
	categoryVPCNetwork + "/multipleSubnets":        {"reliability"},        // VPC
	categoryVPCNetwork + "/openAllPorts":           {"hipaa", "pci"},       // VPC
	categoryVPCNetwork + "/privateAccessEnabled":   {"pci"},                // VPC
}

func (c *cloudSploitFinding) setTags() {
	if tags, ok := pluginTagMap[c.Category+"/"+c.Plugin]; ok {
		c.Tags = tags
	}
}

// scoreMap (key: `{Categor}/{Plugin}`, value: score)
var scoreMap = map[string]float32{
	categorySQL + "/dbPubliclyAccessible":               0.8, // CloudSQL
	categoryCompute + "/instanceLeastPrivilege":         0.6, // GCE
	categoryStorage + "/bucketAllUsersPolicy":           0.6, // GCS
	categoryKubernetes + "/loggingEnabled":              0.6, // GKE
	categoryIAM + "/corporateEmailsOnly":                0.8, // IAM
	categoryIAM + "/serviceAccountAdmin":                0.6, // IAM
	categoryIAM + "/serviceAccountUser":                 0.6, // IAM
	categoryVPCNetwork + "/openAllPorts":                0.8, // VPC
	categoryVPCNetwork + "/openCIFS":                    0.8, // VPC
	categoryVPCNetwork + "/openDNS":                     0.8, // VPC
	categoryVPCNetwork + "/openDocker":                  0.8, // VPC
	categoryVPCNetwork + "/openFTP":                     0.8, // VPC
	categoryVPCNetwork + "/openHadoopNameNode":          0.8, // VPC
	categoryVPCNetwork + "/openHadoopNameNodeWebUI":     0.8, // VPC
	categoryVPCNetwork + "/openKibana":                  0.8, // VPC
	categoryVPCNetwork + "/openMySQL":                   0.8, // VPC
	categoryVPCNetwork + "/openNetBIOS":                 0.8, // VPC
	categoryVPCNetwork + "/openOracle":                  0.8, // VPC
	categoryVPCNetwork + "/openOracleAutoDataWarehouse": 0.8, // VPC
	categoryVPCNetwork + "/openPostgreSQL":              0.8, // VPC
	categoryVPCNetwork + "/openRDP":                     0.8, // VPC
	categoryVPCNetwork + "/openRPC":                     0.8, // VPC
	categoryVPCNetwork + "/openSMBoTCP":                 0.8, // VPC
	categoryVPCNetwork + "/openSMTP":                    0.8, // VPC
	categoryVPCNetwork + "/openSQLServer":               0.8, // VPC
	categoryVPCNetwork + "/openSSH":                     0.6, // VPC
	categoryVPCNetwork + "/openSalt":                    0.8, // VPC
	categoryVPCNetwork + "/openTelnet":                  0.8, // VPC
	categoryVPCNetwork + "/openVNCClient":               0.8, // VPC
	categoryVPCNetwork + "/openVNCServer":               0.8, // VPC
}

func (c *cloudSploitFinding) getScore() float32 {
	switch strings.ToUpper(c.Status) {
	case resultOK:
		return 0.0
	case resultUNKNOWN:
		return 0.1
	case resultWARN:
		return 0.3
	default:
		// FAIL
		if score, ok := scoreMap[c.Category+"/"+c.Plugin]; ok {
			return score
		}
		return 0.3
	}
}
