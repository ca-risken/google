FROM golang:1.17 as builder
WORKDIR /go/src/github.com/ca-risken/google/src/cloudsploit/
ADD *.go go.* ./
ENV CGO_ENABLED=0 GOPRIVATE="github.com/ca-risken/*"
ARG GITHUB_USER
ARG GITHUB_TOKEN
RUN echo "machine github.com" > ~/.netrc
RUN echo "login $GITHUB_USER" >> ~/.netrc
RUN echo "password $GITHUB_TOKEN" >> ~/.netrc
RUN go build && cp cloudsploit /go/bin/

FROM public.ecr.aws/risken/base/cloudsploit-base:v0.0.1
COPY --from=builder /go/bin/cloudsploit /usr/local/cloudsploit/bin/
ENV DEBUG= \
  PROFILE_EXPORTER= \
  PROFILE_TYPES= \
  AWS_REGION= \
  AWS_ACCESS_KEY_ID= \
  AWS_SECRET_ACCESS_KEY= \
  AWS_SESSION_TOKEN= \
  AWS_XRAY_SDK_DISABLED=TRUE \
  AWS_XRAY_CONTEXT_MISSING=LOG_ERROR \
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
