TARGETS = asset cloudsploit google portscan scc
BUILD_TARGETS = $(TARGETS:=.build)
BUILD_CI_TARGETS = $(TARGETS:=.build-ci)
IMAGE_PUSH_TARGETS = $(TARGETS:=.push-image)
MANIFEST_CREATE_TARGETS = $(TARGETS:=.create-manifest)
MANIFEST_PUSH_TARGETS = $(TARGETS:=.push-manifest)
TEST_TARGETS = $(TARGETS:=.go-test)
LINT_TARGETS = $(TARGETS:=.lint)
BUILD_OPT=""
IMAGE_TAG=latest
MANIFEST_TAG=latest
IMAGE_PREFIX=google
IMAGE_REGISTRY=local

.PHONY: all
all: build

.PHONY: install
install:
	go get \
		google.golang.org/grpc \
		github.com/golang/protobuf/protoc-gen-go \
		github.com/grpc-ecosystem/go-grpc-middleware

.PHONY: clean
clean:
	rm -f proto/**/*.pb.go
	rm -f doc/*.md

.PHONY: fmt
fmt: proto/**/*.proto
	clang-format -i proto/**/*.proto

.PHONY: proto-doc
proto-doc: fmt
	protoc \
		--proto_path=proto \
		--error_format=gcc \
		--doc_out=markdown,README.md:doc \
		proto/**/*.proto;

.PHONY: proto
proto: fmt
	protoc \
		--proto_path=proto \
		--error_format=gcc \
		--go_out=plugins=grpc,paths=source_relative:proto \
		proto/**/*.proto;

.PHONY: build
build: $(BUILD_TARGETS)
%.build: %.go-test
	. env.sh && TARGET=$(*) IMAGE_TAG=$(IMAGE_TAG) IMAGE_PREFIX=$(IMAGE_PREFIX) BUILD_OPT="$(BUILD_OPT)" . hack/docker-build.sh

.PHONY: build-ci
build-ci: $(BUILD_CI_TARGETS)
%.build-ci: FAKE
	TARGET=$(*) IMAGE_TAG=$(IMAGE_TAG) IMAGE_PREFIX=$(IMAGE_PREFIX) BUILD_OPT="$(BUILD_OPT)" . hack/docker-build.sh
	docker tag $(IMAGE_PREFIX)/$(*):$(IMAGE_TAG) $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG)

.PHONY: push-image
push-image: $(IMAGE_PUSH_TARGETS)
%.push-image: FAKE
	docker push $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG)

.PHONY: create-manifest
create-manifest: $(MANIFEST_CREATE_TARGETS)
%.create-manifest: FAKE
	docker manifest create $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(MANIFEST_TAG) $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG_BASE)_linux_amd64 $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG_BASE)_linux_arm64
	docker manifest annotate --arch amd64 $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(MANIFEST_TAG) $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG_BASE)_linux_amd64
	docker manifest annotate --arch arm64 $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(MANIFEST_TAG) $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG_BASE)_linux_arm64

.PHONY: push-manifest
push-manifest: $(MANIFEST_PUSH_TARGETS)
%.push-manifest: FAKE
	docker manifest push $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(MANIFEST_TAG)
	docker manifest inspect $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(MANIFEST_TAG)

.PHONY: go-test proto-test pkg-test
go-test: $(TEST_TARGETS) proto-test pkg-test
%.go-test: FAKE
	cd src/$(*) && go test ./...
proto-test:
	cd proto/google    && go test ./...
pkg-test:
	cd pkg/common      && go test ./...

.PHONY: go-mod-tidy
go-mod-tidy: proto
	cd proto/google    && go mod tidy
	cd pkg/common      && go mod tidy
	cd src/google      && go mod tidy
	cd src/asset       && go mod tidy
	cd src/cloudsploit && go mod tidy
	cd src/scc         && go mod tidy
	cd src/portscan    && go mod tidy

.PHONY: go-mod-update
go-mod-update:
	cd src/google \
		&& go get \
			github.com/ca-risken/google/proto/...
	cd src/asset \
		&& go get \
			github.com/ca-risken/core/proto/... \
			github.com/ca-risken/google/proto/...
	cd src/cloudsploit \
		&& go get \
			github.com/ca-risken/core/proto/... \
			github.com/ca-risken/google/proto/...
	cd src/scc \
		&& go get \
			github.com/ca-risken/core/proto/... \
			github.com/ca-risken/google/proto/...
	cd src/portscan \
		&& go get \
			github.com/ca-risken/core/proto/... \
			github.com/ca-risken/google/proto/...

.PHONY: lint proto-lint pkg-lint
lint: $(LINT_TARGETS) proto-lint pkg-lint
%.lint: FAKE
	sh hack/golinter.sh src/$(*)
proto-lint:
	sh hack/golinter.sh proto/google
pkg-lint:
	sh hack/golinter.sh pkg/common

FAKE: