# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Building and Testing
- Install dependencies: `make install`
- Build all services: `make build`
- Run all tests: `make go-test`
- Lint code: `make lint`
- Generate code: `make generate`

### Individual Service Building
Available services: asset, cloudsploit, portscan, scc
- Build specific service: `TARGET=<service> IMAGE_TAG=<tag> IMAGE_PREFIX=google . hack/docker-build.sh`

### Docker Operations
- Build for CI: `make build-ci`
- Push images: `make push-image`
- Create multi-arch manifests: `make create-manifest`
- Push manifests: `make push-manifest`

## Architecture

This is the Google Cloud Platform security monitoring module for RISKEN. It consists of four main services:

### Core Services
1. **Asset Service** (`pkg/asset/`, `cmd/asset/`)
   - Scans Google Cloud assets using Cloud Asset API
   - Handles IAM policies, storage buckets, and service accounts
   - Uses exponential backoff for API retry logic

2. **CloudSploit Service** (`pkg/cloudsploit/`, `cmd/cloudsploit/`)
   - Integrates with CloudSploit security scanner
   - Uses template-based configuration
   - Manages memory limits for scans

3. **Security Command Center (SCC) Service** (`pkg/scc/`, `cmd/scc/`)
   - Interfaces with Google Security Command Center
   - Handles vulnerability data and findings

4. **Port Scan Service** (`pkg/portscan/`, `cmd/portscan/`)
   - Performs network port scanning using nmap
   - Generates security findings for open ports

### Shared Components
- **Common Package** (`pkg/common/`): Utilities for resource naming, tagging, and string manipulation
- **gRPC Client** (`pkg/grpc/`): Client for communication with RISKEN core services
- **SQS Integration** (`pkg/sqs/`): AWS SQS message handling for job processing

### Configuration Requirements
- Google service account credentials file (default: `/tmp/credential.json`)
- Environment variables for service endpoints (core, datasource-api)
- AWS credentials for SQS integration

### Testing Strategy
Tests are co-located with source files using `*_test.go` naming convention. All services include unit tests with mock interfaces.

### Deployment
Services are containerized and deployed to Kubernetes. Each service has its own Dockerfile in `dockers/<service>/`.