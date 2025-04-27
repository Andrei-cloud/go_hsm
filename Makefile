.PHONY: help runhsm build test fmt lint clean

help: ## Display this help screen.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } ' $(MAKEFILE_LIST)

run: ## Start HSM server.
	go run ./cmd/go_hsm/main.go

build: ## Build HSM binary.
	CGO_ENABLED=0 go build -o bin/go_hsm ./cmd/go_hsm/main.go

test: ## Run tests.
	go test ./... -v

clean: ## Clean built binaries.
	rm -rf bin
