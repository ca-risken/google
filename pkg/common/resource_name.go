package common

import "strings"

// GetShortName return short resoruce name from slash chain format. e.g. "//{service}.googleapis.com/projects/{your-project}/{service}/{your-resource}"
func GetShortName(name string) string {
	// "name": "//iam.googleapis.com/projects/vulnasses/serviceAccounts/cloudsploit-scans@vulnasses.iam.gserviceaccount.com"
	array := strings.Split(name, "/")
	return array[len(array)-1]
}

// GetResourceName return common resoruce name format (`prjectID/serviceName/your-resouce`)
func GetResourceName(gcpProjectID, serviceName, resourceName string) string {
	return gcpProjectID + "/" + serviceName + "/" + resourceName
}
