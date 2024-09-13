FROM golang:1.21.3 as builder
WORKDIR /go/src/github.com/ca-risken/google/
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -o /go/bin/cloudsploit cmd/cloudsploit/main.go

FROM node:lts-alpine3.12 as cloudsploit
# 2022/12/14時点で最新
ARG CLOUDSPLOIT_COMMIT_HASH=9f467ff72d75faf76bfe8fee52cca503b2b78191
RUN apk add --no-cache ca-certificates tzdata git \
  && mkdir -p /opt/cloudsploit \
  && cd /opt/cloudsploit \
  && git init \
  && git remote add origin https://github.com/aquasecurity/cloudsploit.git \
  && git fetch origin ${CLOUDSPLOIT_COMMIT_HASH} --depth 1 \
  && git checkout FETCH_HEAD \
  && yarn install  \
  && chmod +x index.js

FROM public.ecr.aws/risken/base/risken-base:v0.0.1 as risken-base

FROM node:lts-alpine3.12
COPY --from=builder /go/bin/cloudsploit /usr/local/cloudsploit/bin/
COPY --from=cloudsploit /opt/cloudsploit /opt/cloudsploit
COPY --from=risken-base /usr/local/bin/env-injector /usr/local/bin/
ENV DEBUG= \
  PROFILE_EXPORTER= \
  PROFILE_TYPES= \
  AWS_REGION= \
  AWS_ACCESS_KEY_ID= \
  AWS_SECRET_ACCESS_KEY= \
  AWS_SESSION_TOKEN= \
  SQS_ENDPOINT= \
  CLOUD_SPLOIT_QUEUE_NAME= \
  CLOUD_SPLOIT_QUEUE_URL= \
  MAX_NUMBER_OF_MESSAGE= \
  WAIT_TIME_SECOND=20 \
  FINDING_SVC_ADDR= \
  ALERT_SVC_ADDR= \
  GOOGLE_SVC_ADDR= \
  CLOUD_SPLOIT_COMMAND="/opt/cloudsploit/index.js" \
  GOOGLE_SERVICE_ACCOUNT_EMAIL= \
  GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY= \
  TZ=Asia/Tokyo
WORKDIR /usr/local/cloudsploit
ENTRYPOINT ["env-injector"]
CMD ["bin/cloudsploit"]
