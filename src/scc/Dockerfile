FROM golang:1.18.2 as builder
WORKDIR /go/src/github.com/ca-risken/google/src/scc/
ADD *.go go.* ./
ARG GITHUB_USER
ARG GITHUB_TOKEN
RUN echo "machine github.com" > ~/.netrc
RUN echo "login $GITHUB_USER" >> ~/.netrc
RUN echo "password $GITHUB_TOKEN" >> ~/.netrc
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -o /go/bin/

FROM public.ecr.aws/risken/base/risken-base:v0.0.1
COPY --from=builder /go/bin/scc /usr/local/scc/bin/
ADD docker-entrypoint.sh /usr/local/bin
ENV DEBUG= \
    PROFILE_EXPORTER= \
    PROFILE_TYPES= \
    AWS_REGION= \
    AWS_ACCESS_KEY_ID= \
    AWS_SECRET_ACCESS_KEY= \
    AWS_SESSION_TOKEN= \
    SQS_ENDPOINT= \
    SCC_QUEUE_NAME= \
    SCC_QUEUE_URL= \
    MAX_NUMBER_OF_MESSAGE= \
    WAIT_TIME_SECOND=20 \
    FINDING_SVC_ADDR= \
    ALERT_SVC_ADDR= \
    GOOGLE_SVC_ADDR= \
    GOOGLE_CREDENTIAL_PATH= \
    GOOGLE_SERVICE_ACCOUNT_JSON= \
    TZ=Asia/Tokyo
WORKDIR /usr/local/scc
ENTRYPOINT ["env-injector", "docker-entrypoint.sh"]
CMD ["bin/scc"]
