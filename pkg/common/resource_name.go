package common

import "strings"

// UnknownService unknown service name label
const UnknownService string = "unknown"

// GetShortResourceName return short resoruce name from `fullResourceName`. (Resource name format: https://cloud.google.com/asset-inventory/docs/resource-name-format)
func GetShortResourceName(gcpProjectID, fullResourceName string) string {
	service := GetServiceName(fullResourceName)
	array := strings.Split(fullResourceName, "/")
	if len(array) < 2 {
		return getResourceName(gcpProjectID, service, fullResourceName)
	}
	return getResourceName(gcpProjectID, service, array[len(array)-1])
}

// getResourceName return `{gcpProjectID}/{serviceName}/{resourceName}`
func getResourceName(gcpProjectID, serviceName, resourceName string) string {
	return gcpProjectID + "/" + serviceName + "/" + resourceName
}

// GetServiceName return service name from `fullResourceName`. (Resource name format: https://cloud.google.com/asset-inventory/docs/resource-name-format)
func GetServiceName(fullResourceName string) string {
	array := strings.Split(strings.Replace(fullResourceName, "//", "", 1), "/")
	if len(array) < 1 {
		return UnknownService
	}
	svc := array[0]
	if !strings.Contains(svc, ".googleapis.com") {
		return UnknownService
	}
	return strings.ReplaceAll(svc, ".googleapis.com", "")
}
