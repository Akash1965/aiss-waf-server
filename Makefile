.PHONY: all build test test-race bench lint clean docker-build docker-up docker-down install

BINARY     := aiss-agent
BUILD_DIR  := ./dist
CMD_PATH   := ./cmd/agent
MODULE     := github.com/aiss/agent
LDFLAGS    := -ldflags="-s -w -X $(MODULE)/internal/version.Version=$(shell git describe --tags --always 2>/dev/null || echo dev)"

all: test build

## build: Compile the AISS agent binary
build:
	@echo "==> Building $(BINARY)..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) $(CMD_PATH)
	@echo "==> Binary: $(BUILD_DIR)/$(BINARY)"

## test: Run all unit and integration tests
test:
	@echo "==> Running tests..."
	go test -v -count=1 ./...

## test-race: Run tests with race detector
test-race:
	@echo "==> Running tests with race detector..."
	go test -race -v -count=1 ./...

## test-short: Run only fast unit tests (skip integration)
test-short:
	@echo "==> Running unit tests..."
	go test -short -v ./...

## bench: Run benchmark tests
bench:
	@echo "==> Running benchmarks..."
	go test -bench=. -benchmem -count=3 ./...

## cover: Generate coverage report
cover:
	@echo "==> Coverage report..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "==> Report: coverage.html"

## lint: Run golangci-lint
lint:
	@echo "==> Linting..."
	golangci-lint run ./...

## vet: Run go vet
vet:
	go vet ./...

## tidy: Tidy go modules
tidy:
	go mod tidy

## clean: Remove build artifacts
clean:
	@rm -rf $(BUILD_DIR) coverage.out coverage.html
	@echo "==> Cleaned"

## docker-build: Build and test inside Docker (full stack)
docker-build:
	@echo "==> Building Docker image (runs all tests)..."
	docker build -t aiss:latest .
	@echo "==> Docker image built. View test results:"
	@echo "    docker run --rm aiss:latest cat /app/test-results.txt"

## docker-up: Start the full AISS stack
docker-up:
	docker compose up -d --build
	@echo "==> Stack started. Nginx on :80, Dashboard server on :8080"

## docker-down: Stop the full stack
docker-down:
	docker compose down -v

## docker-test: Run tests in Docker then view results
docker-test:
	@$(MAKE) docker-build
	@docker run --rm aiss:latest cat /app/test-results.txt

## run-dev: Run agent locally (requires ./rules and ./aiss.conf)
run-dev:
	go run $(CMD_PATH) --config ./aiss.conf

## load-test: Run load test with wrk (requires wrk to be installed)
load-test:
	@echo "==> Load test: 10k RPS target..."
	wrk -t12 -c400 -d30s --latency http://localhost/api/test

## install: Install nginx module and agent to system (Ubuntu)
install:
	@bash scripts/install.sh

help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'
