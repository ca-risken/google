#!/bin/bash -e

# github
export GITHUB_USER="your-name"
export GITHUB_TOKEN="your-token"

# GO
export GOPRIVATE="github.com/CyberAgent/*"

# DB
export DB_MASTER_HOST="db"
export DB_MASTER_USER="hoge"
export DB_MASTER_PASSWORD="moge"
export DB_SLAVE_HOST="db"
export DB_SLAVE_USER="hoge"
export DB_SLAVE_PASSWORD="moge"
export DB_LOG_MODE="false"

# Google
export PORT="11001"
export DEBUG="true"
export AWS_REGION="ap-northeast-1"
export SQS_ENDPOINT="http://sqs:9324"
export ASSET_QUEUE_NAME="google-asset"
export ASSET_QUEUE_URL="http://sqs:9324/queue/google-asset"
export CLOUD_SPLOIT_QUEUE_NAME="google-cloudsploit"
export CLOUD_SPLOIT_QUEUE_URL="http://sqs:9324/queue/google-cloudsploit"
export GOOGLE_CREDENTIAL_PATH="/path/to/your-credential-file"
export GOOGLE_SERVICE_ACCOUNT_JSON='{"key": "your credential json here..." }'
export GOOGLE_SERVICE_ACCOUNT_EMAIL="risken@ca-security-hub.iam.gserviceaccount.com"
export GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY="your private key here..."

# gRPC server
export FINDING_SVC_ADDR="finding:8001"
export ALERT_SVC_ADDR="alert:8004"
export GOOGLE_SVC_ADDR="google:11001"
