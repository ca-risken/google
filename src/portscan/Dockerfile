FROM golang:1.16 as builder
WORKDIR /go/src/github.com/CyberAgent/mimosa-google/src/portscan/
ADD *.go go.* ./
ENV CGO_ENABLED=0 GOPRIVATE="github.com/CyberAgent/*,github.com/ca-risken/*"
ARG ENV_INJECTOR_VERSION=v0.0.6
ARG GITHUB_USER
ARG GITHUB_TOKEN
RUN echo "machine github.com" > ~/.netrc
RUN echo "login $GITHUB_USER" >> ~/.netrc
RUN echo "password $GITHUB_TOKEN" >> ~/.netrc
RUN go build && cp portscan /go/bin/

WORKDIR /go/src/github.com/gassara-kys
RUN git clone https://github.com/gassara-kys/env-injector.git -b ${ENV_INJECTOR_VERSION} \
    && cd env-injector \
    && go build \
    && cp env-injector /go/bin/

FROM alpine
RUN apk add --no-cache ca-certificates tzdata nmap nmap-scripts
COPY --from=builder /go/bin/env-injector /usr/local/bin/
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
    MAX_NUMBER_OF_MESSAGE=10 \
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
