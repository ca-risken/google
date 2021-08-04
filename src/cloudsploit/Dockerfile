FROM golang AS builder
WORKDIR /go/src/github.com/CyberAgent/mimosa-google/src/cloudsploit/
ADD *.go go.* ./
ENV CGO_ENABLED=0 GO111MODULE=on GOPRIVATE="github.com/CyberAgent/*"
ARG GITHUB_USER
ARG GITHUB_TOKEN
RUN echo "machine github.com" > ~/.netrc
RUN echo "login $GITHUB_USER" >> ~/.netrc
RUN echo "password $GITHUB_TOKEN" >> ~/.netrc
RUN go install -v

FROM node:lts-alpine3.12
RUN apk add --no-cache ca-certificates tzdata git \
  && mkdir -p /var/scan/ && cd /var/scan/ \
  && git clone https://github.com/aquasecurity/cloudsploit.git -b v2.0.0 --depth 1 \
  && npm init --yes && npm install cloudsploit \
  && cd /tmp/ && wget -q https://github.com/gassara-kys/env-injector/releases/download/v0.0.6/env-injector_0.0.6_Linux_x86_64.tar.gz \
  && tar xvfz env-injector_0.0.6_Linux_x86_64.tar.gz && mv env-injector /usr/local/bin/ && rm -rf /tmp/*
COPY --from=builder /go/bin/cloudsploit /usr/local/cloudsploit/bin/
ENV PATH="$PATH:/var/scan/node_modules/.bin" \
    DEBUG= \
    AWS_REGION= \
    AWS_ACCESS_KEY_ID= \
    AWS_SECRET_ACCESS_KEY= \
    AWS_SESSION_TOKEN= \
    AWS_XRAY_SDK_DISABLED=TRUE \
    AWS_XRAY_CONTEXT_MISSING=LOG_ERROR \
    SQS_ENDPOINT= \
    CLOUD_SPLOIT_QUEUE_NAME= \
    CLOUD_SPLOIT_QUEUE_URL= \
    MAX_NUMBER_OF_MESSAGE=10 \
    WAIT_TIME_SECOND=20 \
    FINDING_SVC_ADDR= \
    ALERT_SVC_ADDR= \
    GOOGLE_SVC_ADDR= \
    CLOUD_SPLOIT_COMMAND="cloudsploit-scan" \
    GOOGLE_SERVICE_ACCOUNT_EMAIL= \
    GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY= \
    TZ=Asia/Tokyo
WORKDIR /usr/local/cloudsploit
ENTRYPOINT ["env-injector"]
CMD ["bin/cloudsploit"]
