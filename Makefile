.PHONY: build install test clean release help

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Binary names
BINARY_NAME=hoot
BINARY_UNIX=$(BINARY_NAME)_unix

# Version from git tag or default
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "0.0.4")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION)"

# Main targets
all: test build

build: 
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) .

install:
	$(GOCMD) install $(LDFLAGS) ./...

test: 
	$(GOTEST) -v ./...

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_UNIX)

# Cross-compilation
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-linux-arm64 .

build-darwin:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-darwin-amd64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-darwin-arm64 .

build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-windows-amd64.exe .

build-all: build-linux build-darwin build-windows

# Release with GoReleaser
release:
	goreleaser release --clean

release-snapshot:
	goreleaser release --snapshot --clean

# Development
run:
	$(GOCMD) run .

fmt:
	$(GOCMD) fmt ./...

lint:
	golangci-lint run ./...

# Docker (optional)
docker-build:
	docker build -t hoot:latest .

docker-run:
	docker run --rm -it hoot:latest

help:
	@echo "hoot Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make build          Build binary"
	@echo "  make install        Install to GOPATH/bin"
	@echo "  make test           Run tests"
	@echo "  make clean          Remove binaries"
	@echo "  make build-all      Cross-compile for all platforms"
	@echo "  make release        Create release with GoReleaser"
	@echo "  make release-snapshot  Test release locally"
	@echo "  make fmt            Format code"
	@echo "  make lint           Run linter"
	@echo ""
	@echo "Install options:"
	@echo "  VERSION=x.x.x      Override version (default: git tag)"
