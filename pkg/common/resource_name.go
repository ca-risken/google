package common

import "strings"

// UnknownService unknown service name label
const UnknownService string = "unknown"

// GetShortResourceName return short resoruce name from `fullResourceName`. (Resource name format: https://cloud.google.com/asset-inventory/docs/resource-name-format)
func GetShortResourceName(gcpProjectID, fullResourceName string) string {
	array := strings.Split(fullResourceName, "/")
	if len(array) < 2 {
		return getResourceName(gcpProjectID, UnknownService, fullResourceName)
	}
	return getResourceName(gcpProjectID, array[len(array)-2], array[len(array)-1])
}

// getResourceName return `{gcpProjectID}/{serviceName}/{resourceName}`
func getResourceName(gcpProjectID, serviceName, resourceName string) string {
	return gcpProjectID + "/" + serviceName + "/" + resourceName
}
