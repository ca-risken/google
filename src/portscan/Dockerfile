FROM golang:1.16 as builder
WORKDIR /go/src/github.com/ca-risken/google/src/portscan/
ADD *.go go.* ./
ENV CGO_ENABLED=0 GOPRIVATE="github.com/ca-risken/*"
ARG GITHUB_USER
ARG GITHUB_TOKEN
RUN echo "machine github.com" > ~/.netrc
RUN echo "login $GITHUB_USER" >> ~/.netrc
RUN echo "password $GITHUB_TOKEN" >> ~/.netrc
RUN go build && cp portscan /go/bin/

FROM public.ecr.aws/risken/base/risken-base:v0.0.1
RUN apk add --no-cache nmap nmap-scripts
COPY --from=builder /go/bin/portscan /usr/local/portscan/bin/
ADD docker-entrypoint.sh /usr/local/bin
ENV DEBUG= \
    AWS_REGION= \
    AWS_ACCESS_KEY_ID= \
    AWS_SECRET_ACCESS_KEY= \
    AWS_SESSION_TOKEN= \
    AWS_XRAY_SDK_DISABLED=TRUE \
    AWS_XRAY_CONTEXT_MISSING=LOG_ERROR \
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
ENTRYPOINT ["env-injector", "docker-entrypoint.sh"]
CMD ["bin/portscan"]
