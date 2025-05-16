.PHONY: help run run-human build test fmt lint clean plugins cli install plugin-gen gen-plugins build-plugins

# Plugin tools and directories
WASM_OUT_DIR := ./plugins
PLUGIN_GEN := ./bin/plugingen
VERSION ?= 1.0.0
AUTHOR ?= "HSM Plugin Generator"

help: ## Display this help screen.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } ' $(MAKEFILE_LIST)

gen: plugin-gen ## Generate plugin code
	@echo "Generating plugin code..."
	@for d in commands/*; do \
		if [ -d $$d ]; then \
			name=$$(basename $$d); \
			desc=$$(grep -h "^func Execute$$name" "$$d/gen.go" | sed -E 's/^.*\/\/ *//'); \
			if [ -z "$$desc" ]; then \
				desc="HSM command $$name implementation"; \
			fi; \
			echo "  - $$name"; \
			$(PLUGIN_GEN) \
				-cmd $$name \
				-logic github.com/andrei-cloud/go_hsm/internal/hsm/logic \
				-version $(VERSION) \
				-desc "$$desc" \
				-author $(AUTHOR) \
				-out ./commands/$$name; \
		fi; \
	done

plugins: gen ## Build WASM plugins
	@echo "Building WASM plugins with TinyGo..."
	@rm -f $(WASM_OUT_DIR)/*.wasm
	@for d in commands/*; do \
		if [ -d "$$d" ]; then \
			name=$$(basename "$$d"); \
			echo "  - $$name.wasm"; \
			if [ -f "./commands/$$name/main.go" ]; then \
				if tinygo build -o "$(WASM_OUT_DIR)/$$name.wasm" \
					-target=wasi -scheduler=none -opt=z -no-debug \
					"./commands/$$name/main.go"; then \
					rm "./commands/$$name/main.go"; \
					echo "    Cleaned up generated code"; \
				fi; \
			else \
				echo "    Skipping - no main.go"; \
			fi; \
		fi; \
	done

run: ## Start HSM server with debug logging.
	@HUMAN=true DEBUG=true go run ./cmd/go_hsm/main.go serve \
		--plugin-dir=$(WASM_OUT_DIR) \
		 --debug

run-release: ## Start HSM server in release mode.
	@go run ./cmd/go_hsm/main.go serve \
		--plugin-dir=$(WASM_OUT_DIR)

build: ## Build HSM binary.
	CGO_ENABLED=0 go build -o bin/go_hsm ./cmd/go_hsm/main.go

test: ## Run tests.
	go test -failfast -v ./...

clean: ## Clean built binaries and plugins.
	rm -rf bin $(WASM_OUT_DIR)

# CLI-specific targets.
.PHONY: cli install

cli: ## Build CLI binary.
	go build -o bin/go_hsm ./cmd/go_hsm

install: cli ## Install CLI to GOPATH/bin.
	cp bin/go_hsm $(GOPATH)/bin/

