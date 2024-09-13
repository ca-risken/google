FROM golang:1.21.3 as builder
WORKDIR /go/src/github.com/ca-risken/google/
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -o /go/bin/asset cmd/asset/main.go

FROM public.ecr.aws/risken/base/risken-base:v0.0.1
COPY --from=builder /go/bin/asset /usr/local/asset/bin/
COPY dockers/docker-entrypoint-google-credential.sh /usr/local/bin
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
ENTRYPOINT ["env-injector", "docker-entrypoint-google-credential.sh"]
CMD ["bin/asset"]
