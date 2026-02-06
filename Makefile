# Makefile for the OrigAdmin Framework Contrib module

# ============================================================================ #
#                              CONFIGURATION
# ============================================================================ #

# --------------------------- Basic Configuration ---------------------------- #
GOHOSTOS         ?= $(shell go env GOHOSTOS)
ENV              ?= dev
PROJECT_ORG      := OrigAdmin
THIRD_PARTY_PATH := ./third_party
BUILT_BY         := $(PROJECT_ORG)

# ---------------------------- Git Information ----------------------------- #
GIT_COMMIT      := $(shell git rev-parse --short HEAD)
GIT_BRANCH      := $(shell git rev-parse --abbrev-ref HEAD)
GIT_VERSION     := $(shell git describe --tags --always)

# ------------------------- OS-Specific Variables -------------------------- #
ifeq ($(GOHOSTOS), windows)
    SHELL          := powershell.exe
    .SHELLFLAGS    := -NoProfile -Command
    RM_RF          := Remove-Item -Recurse -Force
    GIT_HEAD_TAG   := $(shell git tag --points-at HEAD 2>$$null)
    BUILD_DATE     := $(shell powershell -Command "Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK'")
    GIT_TREE_STATE := $(shell powershell -Command "if ((git status --porcelain)) { 'dirty' } else { 'clean' }")
    GIT_TAG        := $(shell powershell -Command "if ('${GIT_HEAD_TAG}') { '${GIT_HEAD_TAG}' } else { '${GIT_COMMIT}' }")
else
    SHELL          := /bin/bash
    RM_RF          := rm -rf
    GIT_HEAD_TAG   := $(shell git tag --points-at HEAD 2>/dev/null)
    BUILD_DATE     := $(shell TZ=Asia/Shanghai date +%FT%T%z)
    GIT_TREE_STATE := $(if $(shell git status --porcelain),dirty,clean)
    GIT_TAG        := $(if $(GIT_HEAD_TAG),$(GIT_HEAD_TAG),$(GIT_COMMIT))
endif

# Append -dirty suffix if the working directory is not clean
ifneq ($(GIT_TREE_STATE), clean)
    GIT_VERSION := $(GIT_VERSION)-dirty
endif

# ----------------------------- Build Flags ------------------------------ #
ifeq ($(ENV), release)
    LDFLAGS = -s -w
endif

# ------------------------ Protobuf Configuration ------------------------ #
# Common protoc include paths, used for both buf and protoc fallback
PROTOC_INCLUDES := -I. -I./api/proto -I$(THIRD_PARTY_PATH)
PROTOC_VERSION := 33.0

# Protoc plugin definitions, used for protoc fallback
PROTOC_GO_OUT       := --go_out=paths=source_relative
PROTOC_GRPC_OUT     := --go-grpc_out=paths=source_relative
PROTOC_HTTP_OUT     := --go-http_out=paths=source_relative
PROTOC_ERRORS_OUT   := --go-errors_out=paths=source_relative
PROTOC_VALIDATE_OUT := --validate_out=lang=go,paths=source_relative
PROTOC_SECURITY_OUT := --go-security_out=paths=source_relative

# A single variable for all proto plugins used in the main API generation
PLUGINS := $(PROTOC_GO_OUT):./api/gen/go \
		$(PROTOC_GRPC_OUT):./api/gen/go \
		$(PROTOC_HTTP_OUT):./api/gen/go \
		$(PROTOC_ERRORS_OUT):./api/gen/go \
		$(PROTOC_VALIDATE_OUT):./api/gen/go

# A single variable for all proto plugins used in example generation (output to current dir)
EXAMPLE_PLUGINS := $(PROTOC_GO_OUT):. \
		$(PROTOC_GRPC_OUT):. \
		$(PROTOC_HTTP_OUT):. \
		$(PROTOC_ERRORS_OUT):. \
		$(PROTOC_SECURITY_OUT):. \
		$(PROTOC_VALIDATE_OUT):.

# Proto file discovery and cleanup commands
ifeq ($(GOHOSTOS), windows)
    API_PROTO_FILES           := $(subst \,/, $(shell powershell -Command "(Get-ChildItem -Recurse ./api/proto -Filter *.proto | Resolve-Path -Relative) -join ' '"))
    TEST_PROTO_FILES          := $(subst \,/, $(shell powershell -Command "(Get-ChildItem -Recurse ./test -Filter *.proto | Resolve-Path -Relative) -join ' '"))
    EXAMPLE_PROTO_FILES       := $(subst \,/, $(shell powershell -Command "(Get-ChildItem -Recurse ./examples -Filter *.proto | Resolve-Path -Relative) -join ' '"))
    CLEAN_EXAMPLE_PROTOS_CMD  := Get-ChildItem -Recurse ./examples -Filter *.pb.go | Remove-Item -Force
    CLEAN_TEST_PROTOS_CMD     := Get-ChildItem -Recurse ./test -Filter *.pb.go | Remove-Item -Force
else
    API_PROTO_FILES           := $(shell find ./api/proto -name '*.proto')
    TEST_PROTO_FILES          := $(shell find ./test -name '*.proto')
    EXAMPLE_PROTO_FILES       := $(shell find ./examples -name '*.proto')
    CLEAN_EXAMPLE_PROTOS_CMD  := find ./examples -name '*.pb.go' -delete
    CLEAN_TEST_PROTOS_CMD     := find ./test -name '*.pb.go' -delete
endif


# ============================================================================ #
#                           LIFECYCLE TARGETS
# ============================================================================ #

.PHONY: all init install-local-protoc deps update update-tools protos example-protos test-protos generate test clean clean-api-gen clean-example-protos clean-test-protos buf-push install-protoc

install-protoc: ## ⬇️ Install protoc compiler
ifeq ($(GOHOSTOS), windows)
	@if (Get-Command protoc -ErrorAction SilentlyContinue) { Write-Host "protoc already installed." } else { \
		Write-Host "Installing protoc for Windows..."; \
		$$ver = "$(PROTOC_VERSION)"; \
		$$zip = "protoc-$$ver-win64.zip"; \
		Invoke-WebRequest -Uri "https://github.com/protocolbuffers/protobuf/releases/download/v$$ver/$$zip" -OutFile "$env:TEMP\$$zip"; \
		Expand-Archive -Path "$env:TEMP\$$zip" -DestinationPath "$env:ProgramFiles"; \
		$env:PATH += ";" + "$env:ProgramFiles\bin"; \
	}
else
	@if command -v protoc >/dev/null 2>&1; then \
		echo "protoc already installed."; \
	else \
		echo "Installing protoc for Linux/macOS..."; \
		UNAME_S=$$(uname -s); \
		if [ "$$UNAME_S" = "Linux" ]; then \
			PROTOC_ZIP="protoc-$(PROTOC_VERSION)-linux-x86_64.zip"; \
			sudo apt-get update && sudo apt-get install -y unzip; \
		elif [ "$$UNAME_S" = "Darwin" ]; then \
			PROTOC_ZIP="protoc-$(PROTOC_VERSION)-osx-x86_64.zip"; \
		else \
			echo "Unsupported OS for protoc auto-install: $$UNAME_S"; \
			exit 1; \
		fi; \
		curl -sSL "https://github.com/protocolbuffers/protobuf/releases/download/v$(PROTOC_VERSION)/$$PROTOC_ZIP" -o "/tmp/$$PROTOC_ZIP"; \
		sudo unzip -o "/tmp/$$PROTOC_ZIP" -d /usr/local; \
		sudo chmod +x /usr/local/bin/protoc; \
		rm "/tmp/$$PROTOC_ZIP"; \
	fi
endif

all: init deps protos example-protos test-protos generate ## ✅ Run the full build process

install-local-protoc: ## 🔧 Install local protoc plugin (protoc-gen-go-security)
ifeq ($(GOHOSTOS), windows)
	@cd ./tools/protoc-gen-go-security; go mod tidy; go install .
else
	@cd ./tools/protoc-gen-go-security && go mod tidy && go install .
endif

init: install-protoc install-local-protoc ## 🔧 Install tools from tools.go, ensuring reproducible builds
	@echo "Ensuring tool dependencies are in go.mod..."
	@go mod tidy
	@echo "Installing tools listed in tools.go..."
	@go install github.com/bufbuild/buf/cmd/buf
	@go install github.com/envoyproxy/protoc-gen-validate
	@go install github.com/go-kratos/kratos/cmd/kratos/v2
	@go install github.com/go-kratos/kratos/cmd/protoc-gen-go-http/v2
	@go install github.com/go-kratos/kratos/cmd/protoc-gen-go-errors/v2
	@go install github.com/google/gnostic/cmd/protoc-gen-openapi
	@go install github.com/google/wire/cmd/wire
	@go install google.golang.org/grpc/cmd/protoc-gen-go-grpc
	@go install google.golang.org/protobuf/cmd/protoc-gen-go

deps: ## 📦 Export and install all third-party protobuf dependencies
	@echo "Updating buf dependencies..."
	@buf dep update
	@echo "Exporting protobuf dependencies to $(THIRD_PARTY_PATH)..."
	@buf export buf.build/origadmin/runtime -o $(THIRD_PARTY_PATH)
	@buf export buf.build/kratos/apis -o $(THIRD_PARTY_PATH)
	@buf export buf.build/bufbuild/protovalidate -o $(THIRD_PARTY_PATH)
	@buf export buf.build/googleapis/googleapis -o $(THIRD_PARTY_PATH)
	@buf export buf.build/protocolbuffers/wellknowntypes -o $(THIRD_PARTY_PATH)
	@buf export buf.build/envoyproxy/protoc-gen-validate -o $(THIRD_PARTY_PATH)
	@buf export buf.build/gnostic/gnostic -o $(THIRD_PARTY_PATH)

update: ## 🔄 Update Go module dependencies (libraries only)
	@echo "Updating Go dependencies..."
	go get -u github.com/goexts/generic@latest
	go get -u github.com/origadmin/toolkits@latest
	go mod tidy

update-tools: ## ⚠️  Update all Go tools in tools.go to latest. High-risk, use with caution!
	@echo "Updating all tools in tools.go to @latest..."
	@go get -u github.com/bufbuild/buf/cmd/buf
	@go get -u github.com/envoyproxy/protoc-gen-validate
	@go get -u github.com/go-kratos/kratos/cmd/kratos/v2
	@go get -u github.com/go-kratos/kratos/cmd/protoc-gen-go-http/v2
	@go get -u github.com/google/gnostic/cmd/protoc-gen-openapi
	@go get -u github.com/google/wire/cmd/wire
	@go get -u google.golang.org/grpc/cmd/protoc-gen-go-grpc
	@go get -u google.golang.org/protobuf/cmd/protoc-gen-go
	@go mod tidy

protos: api-protos test-protos example-protos ## 🧬 Generate all protos
	@echo "Generating all protos done."

api-protos: ## 🧬 Generate API protos (smartly uses buf, falls back to protoc)
	@echo "Generating API protos..."
ifeq ($(GOHOSTOS), windows)
	@if (Get-Command buf -ErrorAction SilentlyContinue) { echo '--> `buf` command found. Using buf to build and generate protos (recommended).'; buf build; buf generate } else { echo '--> WARNING: `buf` command not found. Falling back to protoc.'; echo '--> Please run ''make init'' to install buf for reproducible builds.'; protoc $(PROTOC_INCLUDES) $(PLUGINS) $(API_PROTO_FILES) }
else
	@if command -v buf >/dev/null 2>&1; then \
		echo "--> 'buf' command found. Using buf to build and generate protos (recommended)."; \
		buf build;\
		buf generate;\
	else \
		echo "--> WARNING: 'buf' command not found. Falling back to protoc."; \
		echo "--> Please run 'make init' to install buf for reproducible builds."; \
		protoc $(PROTOC_INCLUDES) $(PLUGINS) $(API_PROTO_FILES); \
	fi
endif

example-protos: ## 🧬 Generate all example protos
	@echo "Generating example protos..."
ifeq ($(GOHOSTOS), windows)
	@protoc $(PROTOC_INCLUDES) $(EXAMPLE_PLUGINS) $(EXAMPLE_PROTO_FILES)
else
	@protoc $(PROTOC_INCLUDES) \
		$(EXAMPLE_PLUGINS) \
		$(EXAMPLE_PROTO_FILES)
endif

test-protos: ## Generate protos for integration tests (cross-platform)
	@echo "Generating protos for integration tests..."
ifeq ($(GOHOSTOS), windows)
    @protoc $(PROTOC_INCLUDES) --go_out=paths=source_relative:. $(TEST_PROTO_FILES)
else
	@protoc $(PROTOC_INCLUDES) --go_out=paths=source_relative:. $(TEST_PROTO_FILES)
endif

test: test-protos example-protos ## 🧪 Run all Go tests
	@go test -v ./...

generate: ## 🧬 Run go generate to generate code (e.g., wire)
	@echo "Running go generate..."
	@go generate ./...


clean: clean-api-gen clean-example-protos clean-test-protos ## 🧹 Clean up all generated files

clean-api-gen: ## 🧹 Clean up API generated files
	@echo "Cleaning up API generated files..."
	@$(RM_RF) ./api/gen

clean-example-protos: ## 🧹 Clean up example generated protos
	@echo "Cleaning up example generated protos..."
	@$(CLEAN_EXAMPLE_PROTOS_CMD)

clean-test-protos: ## 🧹 Clean up test generated protos
	@echo "Cleaning up test generated protos..."
	@$(CLEAN_TEST_PROTOS_CMD)

buf-push: ## 🚀 Push Protobuf module to Buf Schema Registry
	@echo "Pushing Protobuf module to Buf Schema Registry..."
	@buf push

# ============================================================================ #
#                                     HELP
# ============================================================================ #

.PHONY: help

help: ## ✨ Show this help message
	@echo ''
	@echo 'Usage:'
	@echo '  make [target]'
	@echo ''
	@echo 'Targets:'
	@awk '/^[a-zA-Z\-_0-9]+:/ { \
		helpMessage = match(lastLine, /^## (.*)/); \
		if (helpMessage) { \
			helpCommand = substr($$1, 0, index($$1, ":")); \
			helpMessage = substr(lastLine, RSTART + 3, RLENGTH); \
			printf "  \033[36m%-22s\033[0m %s\n", helpCommand, helpMessage; \
		} \
	} \
	{ lastLine = $$0 }' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help
