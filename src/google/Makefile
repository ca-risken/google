####################################################
## grpcurl example
####################################################
.PHONY: all
all: help

.PHONY: help
help:
	@echo "Usage: make <sub-command>"
	@echo "\n---------------- sub-command list ----------------"
	@cat Makefile | grep -e "^.PHONY:" | grep -v "all" | cut -f2 -d' '

.PHONY: list-service
list-service:
	grpcurl -plaintext localhost:11001 list google.google.GoogleService

.PHONY: list-google-datasource
list-google-datasource:
	grpcurl \
		-plaintext \
		-d '{"google_data_source_id":1001}' \
		localhost:11001 google.google.GoogleService.ListGoogleDataSource

.PHONY: list-gcp
list-gcp:
	grpcurl \
		-plaintext \
		-d '{"project_id": 1001}' \
		localhost:11001 google.google.GoogleService.ListGCP

.PHONY: get-gcp
get-gcp:
	grpcurl \
		-plaintext \
		-d '{"project_id": 1001, "gcp_id":1001}' \
		localhost:11001 google.google.GoogleService.GetGCP

.PHONY: put-gcp
put-gcp:
	grpcurl \
		-plaintext \
		-d '{"project_id":1001, "gcp": {"gcp_id":1001, "name":"1", "project_id":1001, "gcp_project_id":"my-project"}}' \
		localhost:11001 google.google.GoogleService.PutGCP

.PHONY: delete-gcp
delete-gcp:
	grpcurl \
		-plaintext \
		-d '{"project_id":1001, "gcp_id":1001}' \
		localhost:11001 google.google.GoogleService.DeleteGCP

.PHONY: list-gcp-datasource
list-gcp-datasource:
	grpcurl \
		-plaintext \
		-d '{"project_id": 1001, "gcp_id":1001}' \
		localhost:11001 google.google.GoogleService.ListGCPDataSource

.PHONY: get-gcp-datasource
get-gcp-datasource:
	grpcurl \
		-plaintext \
		-d '{"project_id": 1001, "gcp_id":1001, "google_data_source_id":1001}' \
		localhost:11001 google.google.GoogleService.GetGCPDataSource

.PHONY: attach-gcp-datasource
attach-gcp-datasource:
	grpcurl \
		-plaintext \
		-d '{"project_id":1001, "gcp_data_source": {"gcp_id":1001, "google_data_source_id":1001 "project_id":1001}}' \
		localhost:11001 google.google.GoogleService.AttachGCPDataSource

.PHONY: detach-gcp-datasource
detach-gcp-datasource:
	grpcurl \
		-plaintext \
		-d '{"project_id":1001, "gcp_id":1001, "google_data_source_id":1001}' \
		localhost:11001 google.google.GoogleService.DetachGCPDataSource

.PHONY: invoke-scan-gcp
invoke-scan-gcp:
	grpcurl \
		-plaintext \
		-d '{"project_id":1001, "gcp_id":1001, "google_data_source_id":1001}' \
		localhost:11001 google.google.GoogleService.InvokeScanGCP

.PHONY: invoke-scan-all
invoke-scan-all:
	grpcurl -plaintext localhost:11001 google.google.GoogleService.InvokeScanAll
