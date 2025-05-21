# Plugin tools and directories 
WASM_OUT_DIR := ./plugins
PLUGIN_GEN := plugingen

.PHONY: help gen plugins run run-release build test clean cli install plugin-gen

help: ## Display this help screen.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } ' $(MAKEFILE_LIST)

plugin-gen: bin/plugingen ## Build plugin generator

bin/plugingen:
	@echo "Building plugin generator..."
	@mkdir -p bin
	@go build -o bin/plugingen ./cmd/plugingen

gen: ## Generate new plugin code
	@echo "Generating new plugin code..."
	@go generate ./internal/commands/plugins/...

plugins: ## Build WASM plugins
	@echo "Building WASM plugins with TinyGo..."
	@if [ -n "$(CMD)" ]; then \
		name=$(CMD); \
		rm -f $(WASM_OUT_DIR)/$$name.wasm; \
		echo "Generating plugin code for $$name..."; \
		go generate "./internal/commands/plugins/$$name/gen.go"; \
		echo "  - $$name.wasm"; \
		if [ -f "./internal/commands/plugins/$$name/main.go" ]; then \
			if tinygo build -o "$(WASM_OUT_DIR)/$$name.wasm" \
				-target=wasi -scheduler=none -opt=z -no-debug \
				"./internal/commands/plugins/$$name/main.go"; then \
				rm "./internal/commands/plugins/$$name/main.go"; \
				echo "    Cleaned up generated code"; \
			fi; \
		else \
			echo "    Skipping - no main.go"; \
		fi; \
	else \
		rm -f $(WASM_OUT_DIR)/*.wasm; \
		$(MAKE) gen; \
		for d in internal/commands/plugins/*; do \
			if [ -d $$d ]; then \
				name=$$(basename "$$d"); \
				echo "  - $$name.wasm"; \
				if [ -f "./internal/commands/plugins/$$name/main.go" ]; then \
					if tinygo build -o "$(WASM_OUT_DIR)/$$name.wasm" \
						-target=wasi -scheduler=none -opt=z -no-debug \
						"./internal/commands/plugins/$$name/main.go"; then \
						rm "./internal/commands/plugins/$$name/main.go"; \
						echo "    Cleaned up generated code"; \
					fi; \
				else \
					echo "    Skipping - no main.go"; \
				fi; \
			fi; \
		done; \
	fi

run: ## Start HSM server with debug logging.
	@go run ./cmd/go_hsm/main.go serve --log-level=info --log-format=human

run-release: ## Start HSM server in release mode.
	@go run ./cmd/go_hsm/main.go serve \
		--plugin-dir=$(WASM_OUT_DIR)

build: ## Build HSM binary.
	CGO_ENABLED=0 go build -o bin/go_hsm ./cmd/go_hsm/main.go

test: ## Run tests.
	go test -failfast -v ./...

clean: ## Clean built binaries and plugins.
	rm -rf bin $(WASM_OUT_DIR)

cli: ## Build CLI binary.
	go build -o bin/go_hsm ./cmd/go_hsm

install: cli ## Install CLI to GOPATH/bin.
	cp bin/go_hsm $(GOPATH)/bin/
