package common

import (
	"encoding/json"

	validation "github.com/go-ozzo/ozzo-validation"
)

const (
	// AssetDataSource is the DataSource label for Cloud Asset Inventory.
	AssetDataSource = "google:asset"
	// CloudSploitDataSource is the DataSource label for Aqua Cloud Sploit.
	CloudSploitDataSource = "google:cloudsploit"
	// SCCDataSource is the DataSource label for Security Command Center.
	SCCDataSource = "google:scc"
)

// GCPQueueMessage is the message for SQS queue
type GCPQueueMessage struct {
	GCPID              uint32 `json:"gcp_id"`
	ProjectID          uint32 `json:"project_id"`
	GoogleDataSourceID uint32 `json:"google_data_source_id"`
}

// Validate is the validation to GuardDutyMessage
func (g *GCPQueueMessage) Validate() error {
	return validation.ValidateStruct(g,
		validation.Field(&g.GCPID, validation.Required),
		validation.Field(&g.ProjectID, validation.Required),
		validation.Field(&g.GoogleDataSourceID, validation.Required),
	)
}

// ParseMessage parse message & validation
func ParseMessage(msg string) (*GCPQueueMessage, error) {
	message := &GCPQueueMessage{}
	if err := json.Unmarshal([]byte(msg), message); err != nil {
		return nil, err
	}
	if err := message.Validate(); err != nil {
		return nil, err
	}
	return message, nil
}
