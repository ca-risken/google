FROM golang:1.21.3 as builder
WORKDIR /go/src/github.com/ca-risken/google/
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -o /go/bin/portscan cmd/portscan/main.go

FROM public.ecr.aws/risken/base/risken-base:v0.0.1
RUN apk add --no-cache nmap nmap-scripts
COPY --from=builder /go/bin/portscan /usr/local/portscan/bin/
COPY dockers/docker-entrypoint-google-credential.sh /usr/local/bin
ENV DEBUG= \
    PROFILE_EXPORTER= \
    PROFILE_TYPES= \
    AWS_REGION= \
    AWS_ACCESS_KEY_ID= \
    AWS_SECRET_ACCESS_KEY= \
    AWS_SESSION_TOKEN= \
    SQS_ENDPOINT= \
    PORTSCAN_QUEUE_NAME= \
    PORTSCAN_QUEUE_URL= \
    MAX_NUMBER_OF_MESSAGE= \
    WAIT_TIME_SECOND=20 \
    FINDING_SVC_ADDR= \
    ALERT_SVC_ADDR= \
    GOOGLE_SVC_ADDR= \
    GOOGLE_CREDENTIAL_PATH= \
    GOOGLE_SERVICE_ACCOUNT_JSON= \
    SCAN_EXCLUDE_PORT_NUMBER= \
    TZ=Asia/Tokyo
WORKDIR /usr/local/portscan
ENTRYPOINT ["env-injector", "docker-entrypoint-google-credential.sh"]
CMD ["bin/portscan"]
