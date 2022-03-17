FROM golang:1.17 as builder
WORKDIR /go/src/github.com/ca-risken/google/src/google/
ADD *.go go.* ./
ENV CGO_ENABLED=0
ARG GITHUB_USER
ARG GITHUB_TOKEN
RUN echo "machine github.com" > ~/.netrc
RUN echo "login $GITHUB_USER" >> ~/.netrc
RUN echo "password $GITHUB_TOKEN" >> ~/.netrc
RUN go build && cp google /go/bin/

FROM public.ecr.aws/risken/base/risken-base:v0.0.1
COPY --from=builder /go/bin/google /usr/local/google/bin/
ADD docker-entrypoint.sh /usr/local/bin
ENV PORT= \
    PROFILE_EXPORTER= \
    PROFILE_TYPES= \
    DB_MASTER_HOST= \
    DB_MASTER_USER= \
    DB_MASTER_PASSWORD= \
    DB_SLAVE_HOST= \
    DB_SLAVE_USER= \
    DB_SLAVE_PASSWORD= \
    DB_SCHEMA=mimosa \
    DB_PORT=3306 \
    DB_LOG_MODE=false \
    AWS_REGION= \
    AWS_ACCESS_KEY_ID= \
    AWS_SECRET_ACCESS_KEY= \
    AWS_SESSION_TOKEN= \
    AWS_XRAY_SDK_DISABLED=TRUE \
    AWS_XRAY_CONTEXT_MISSING=LOG_ERROR \
    SQS_ENDPOINT= \
    ASSET_QUEUE_URL= \
    CLOUD_SPLOIT_QUEUE_URL= \
    PORTSCAN_QUEUE_URL= \
    GOOGLE_CREDENTIAL_PATH= \
    GOOGLE_SERVICE_ACCOUNT_JSON= \
    TZ=Asia/Tokyo
WORKDIR /usr/local/google
ENTRYPOINT ["env-injector", "docker-entrypoint.sh"]
CMD ["bin/google"]
