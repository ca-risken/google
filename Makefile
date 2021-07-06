.PHONY: all install clean network fmt build doc
all: run

install:
	go get \
		google.golang.org/grpc \
		github.com/golang/protobuf/protoc-gen-go \
		github.com/grpc-ecosystem/go-grpc-middleware

clean:
	rm -f proto/**/*.pb.go
	rm -f doc/*.md

fmt: proto/**/*.proto
	clang-format -i proto/**/*.proto

proto-doc: fmt
	protoc \
		--proto_path=proto \
		--error_format=gcc \
		--doc_out=markdown,README.md:doc \
		proto/**/*.proto;

proto: fmt
	protoc \
		--proto_path=proto \
		--error_format=gcc \
		--go_out=plugins=grpc,paths=source_relative:proto \
		proto/**/*.proto;

go-test: proto
	cd proto/google    && go test ./...
	cd pkg/common      && go test ./...
	cd src/google      && go test ./...
	cd src/asset       && go test ./...
	cd src/cloudsploit && go test ./...
	cd src/scc         && go test ./...

go-mod-tidy: proto
	cd proto/google    && go mod tidy
	cd pkg/common      && go mod tidy
	cd src/google      && go mod tidy
	cd src/asset       && go mod tidy
	cd src/cloudsploit && go mod tidy
	cd src/scc         && go mod tidy

go-mod-update:
	cd src/google \
		&& go get -u \
			github.com/CyberAgent/mimosa-google/...
	cd src/asset \
		&& go get -u \
			github.com/CyberAgent/mimosa-core/... \
			github.com/CyberAgent/mimosa-google/...
	cd src/cloudsploit \
		&& go get -u \
			github.com/CyberAgent/mimosa-core/... \
			github.com/CyberAgent/mimosa-google/...
	cd src/scc \
		&& go get -u \
			github.com/CyberAgent/mimosa-core/... \
			github.com/CyberAgent/mimosa-google/...

# @see https://github.com/CyberAgent/mimosa-common/tree/master/local
network:
	@if [ -z "`docker network ls | grep local-shared`" ]; then docker network create local-shared; fi

build: go-test
	. env.sh && docker-compose build

run: build network
	. env.sh && docker-compose up -d

log:
	. env.sh && docker-compose logs -f

log-google:
	. env.sh && docker-compose logs -f google

log-asset:
	. env.sh && docker-compose logs -f asset 

stop:
	. env.sh && docker-compose down
