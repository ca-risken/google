FROM golang:1.21.3 AS builder
WORKDIR /go/src/github.com/ca-risken/google/
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -o /go/bin/asset cmd/asset/main.go

FROM python:3.12-slim
RUN apt-get update && apt-get install -y git ffmpeg libsm6 libxext6 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN pip3 install hawk-scanner==0.3.37
COPY --from=public.ecr.aws/risken/base/risken-base:v0.0.1 /usr/local/bin/env-injector /usr/local/bin/env-injector
RUN chmod +x /usr/local/bin/env-injector
COPY --from=builder /go/bin/asset /usr/local/asset/bin/
COPY dockers/docker-entrypoint-google-credential.sh /usr/local/bin
RUN chmod +x /usr/local/bin/docker-entrypoint-google-credential.sh
ENV DEBUG= \
  PROFILE_EXPORTER= \
  PROFILE_TYPES= \
  AWS_REGION= \
  AWS_ACCESS_KEY_ID= \
  AWS_SECRET_ACCESS_KEY= \
  AWS_SESSION_TOKEN= \
  SQS_ENDPOINT= \
  ASSET_QUEUE_NAME= \
  ASSET_QUEUE_URL= \
  ASSET_API_RETRY_NUM= \
  ASSET_API_RETRY_WAIT_SEC= \
  MAX_NUMBER_OF_MESSAGE= \
  WAIT_TIME_SECOND=20 \
  WAIT_MILLI_SEC_PER_REQUEST= \
  FINDING_SVC_ADDR= \
  ALERT_SVC_ADDR= \
  GOOGLE_SVC_ADDR= \
  GOOGLE_CREDENTIAL_PATH= \
  GOOGLE_SERVICE_ACCOUNT_JSON= \
  TZ=Asia/Tokyo
WORKDIR /usr/local/asset
ENTRYPOINT ["/usr/local/bin/env-injector", "docker-entrypoint-google-credential.sh"]
CMD ["bin/asset"]
