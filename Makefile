.PHONY: help run run-human build test fmt lint clean plugins

help: ## Display this help screen.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } ' $(MAKEFILE_LIST)

run: ## Start HSM server (structured JSON logs).
	HUMAN=true DEBUG=true go run ./cmd/go_hsm/main.go

build: ## Build HSM binary.
	CGO_ENABLED=0 go build -o bin/go_hsm ./cmd/go_hsm/main.go

test: ## Run tests.
	go test ./... -v

clean: ## Clean built binaries.
	rm -rf bin

# build wasm plugin commands.
.PHONY: plugins

plugins: ## compile Go WASM plugins using TinyGo
	@echo "Building wasm plugins with TinyGo..."
	@rm -f commands/*.wasm
	@for d in commands/*; do \
	  if [ -d $$d ]; then \
	    name=$$(basename $$d); \
	    echo "  - $$name.wasm"; \
	    tinygo build -o ./commands/$$name.wasm -target=wasi -scheduler=none \
		-opt=z \
		-no-debug \
		./commands/$$name/main.go; \
	  fi; \
	done

