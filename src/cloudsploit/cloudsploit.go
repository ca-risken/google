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

	Category    string   `json:"category,omitempty"`
	Plugin      string   `json:"plugin,omitempty"`
	Description string   `json:"description,omitempty"`
	Resource    string   `json:"resource,omitempty"`
	Region      string   `json:"region,omitempty"`
	Status      string   `json:"status,omitempty"`
	Message     string   `json:"message,omitempty"`
	Compliance  []string `json:"compliance,omitempty"`
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

// complianceTagMap (key: `{Categor}/{Plugin}`, value: tag)
var complianceTagMap = map[string][]string{
	// CLB
	categoryCLB + "/clbHttpsOnly": []string{"hippa", "pci"},
	// GCE
	categoryCompute + "/csekEncryptionEnabled":  []string{"hippa", "pci"},
	categoryCompute + "/instanceLeastPrivilege": []string{"pci"},
	categoryCompute + "/osLoginEnabled":         []string{"pci"},
	// KMS
	categoryCryptographicKeys + "/keyRotation": []string{"hipaa", "pci"},
	// IAM
	categoryIAM + "/serviceAccountKeyRotation": []string{"hipaa", "pci"},
	// GKE
	categoryKubernetes + "/loggingEnabled": []string{"hipaa"},
	// Logging
	categoryLogging + "/auditConfigurationLogging": []string{"hipaa", "pci"},
	categoryLogging + "/customRoleLogging":         []string{"hipaa"},
	categoryLogging + "/projectOwnershipLogging":   []string{"hipaa", "pci"},
	categoryLogging + "/sqlConfigurationLogging":   []string{"hipaa"},
	categoryLogging + "/storagePermissionsLogging": []string{"hipaa", "pci"},
	categoryLogging + "/vpcFirewallRuleLogging":    []string{"hipaa"},
	categoryLogging + "/vpcNetworkLogging":         []string{"hipaa", "pci"},
	categoryLogging + "/vpcNetworkRouteLogging":    []string{"hipaa"},
	// CloudSQL
	categorySQL + "/dbPubliclyAccessible": []string{"hipaa", "pci"},
	categorySQL + "/dbRestorable":         []string{"pci"},
	categorySQL + "/dbSSLEnabled":         []string{"hipaa", "pci"},
	// GCS
	categoryStorage + "/bucketLogging": []string{"hipaa"},
	// VPC
	categoryVPCNetwork + "/defaultVpcInUse":        []string{"pci"},
	categoryVPCNetwork + "/excessiveFirewallRules": []string{"pci"},
	categoryVPCNetwork + "/flowLogsEnabled":        []string{"hipaa", "pci"},
	categoryVPCNetwork + "/openAllPorts":           []string{"hipaa", "pci"},
	categoryVPCNetwork + "/privateAccessEnabled":   []string{"pci"},
}

func (c *cloudSploitFinding) setCompliance() {
	if tags, ok := complianceTagMap[c.Category+"/"+c.Plugin]; ok {
		c.Compliance = tags
	}
}

// scoreMap (key: `{Categor}/{Plugin}`, value: score)
var scoreMap = map[string]float32{
	// IAM
	categoryIAM + "/corporateEmailsOnly": 0.8,
	categoryIAM + "/serviceAccountAdmin": 0.6,
	// CloudSQL
	categorySQL + "/dbPubliclyAccessible": 0.8,
	// GCS
	categoryStorage + "/bucketAllUsersPolicy": 0.8,
	// VPC
	categoryVPCNetwork + "/openAllPorts":                0.8,
	categoryVPCNetwork + "/openDNS":                     0.6,
	categoryVPCNetwork + "/openDocker":                  0.6,
	categoryVPCNetwork + "/openFTP":                     0.6,
	categoryVPCNetwork + "/openHadoopNameNode":          0.6,
	categoryVPCNetwork + "/openHadoopNameNodeWebUI":     0.6,
	categoryVPCNetwork + "/openKibana":                  0.6,
	categoryVPCNetwork + "/openMySQL":                   0.6,
	categoryVPCNetwork + "/openNetBIOS":                 0.6,
	categoryVPCNetwork + "/openOracle":                  0.6,
	categoryVPCNetwork + "/openOracleAutoDataWarehouse": 0.6,
	categoryVPCNetwork + "/openPostgreSQL":              0.6,
	categoryVPCNetwork + "/openRDP":                     0.6,
	categoryVPCNetwork + "/openRPC":                     0.6,
	categoryVPCNetwork + "/openSMBoTCP":                 0.6,
	categoryVPCNetwork + "/openSMTP":                    0.6,
	categoryVPCNetwork + "/openSQLServer":               0.6,
	categoryVPCNetwork + "/openSSH":                     0.6,
	categoryVPCNetwork + "/openSalt":                    0.6,
	categoryVPCNetwork + "/openTelnet":                  0.6,
	categoryVPCNetwork + "/openVNCClient":               0.6,
	categoryVPCNetwork + "/openVNCServer":               0.6,
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
