FROM golang AS builder
WORKDIR /go/src/github.com/CyberAgent/mimosa-google/src/asset/
ADD *.go go.* ./
ENV CGO_ENABLED=0 GO111MODULE=on GOPRIVATE="github.com/CyberAgent/*"
ARG GITHUB_USER
ARG GITHUB_TOKEN
RUN echo "machine github.com" > ~/.netrc
RUN echo "login $GITHUB_USER" >> ~/.netrc
RUN echo "password $GITHUB_TOKEN" >> ~/.netrc
RUN go install -v

FROM alpine
RUN apk add --no-cache ca-certificates tzdata \
  && cd /tmp/ && wget -q https://github.com/gassara-kys/env-injector/releases/download/v0.0.6/env-injector_0.0.6_Linux_x86_64.tar.gz \
  && tar xvfz env-injector_0.0.6_Linux_x86_64.tar.gz && mv env-injector /usr/local/bin/ && rm -rf /tmp/*
COPY --from=builder /go/bin/asset /usr/local/asset/bin/
ADD docker-entrypoint.sh /usr/local/bin
ENV DEBUG= \
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
ENTRYPOINT ["env-injector", "docker-entrypoint.sh"]
CMD ["bin/asset"]
