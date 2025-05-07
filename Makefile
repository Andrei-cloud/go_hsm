.PHONY: help run run-human build test fmt lint clean plugins cli install

help: ## Display this help screen.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } ' $(MAKEFILE_LIST)

gen: ## Geenerate plugins code.
	go generate ./...

run: ## Start HSM server (structured JSON logs).
	HUMAN=true DEBUG=true go run ./cmd/go_hsm/main.go

build: ## Build HSM binary.
	CGO_ENABLED=0 go build -o bin/go_hsm ./cmd/go_hsm/main.go

test: ## Run tests.
	go test ./... -v

clean: ## Clean built binaries.
	rm -rf bin

all: ## Build, test and clean.
	make gen && make plugins && make run

# build wasm plugin commands.
.PHONY: plugins

plugins: ## compile Go WASM plugins using TinyGo
	@echo "Building wasm plugins with TinyGo..."
	@rm -f commands/*.wasm
	@for d in commands/*; do \
		if [ -d $$d ]; then \
			name=$$(basename $$d); \
			echo "  - $$name.wasm"; \
			if [ -f ./commands/$$name/main.go ]; then \
				tinygo build -o ./commands/$$name.wasm -target=wasi -scheduler=none \
				-opt=z \
				-no-debug \
				./commands/$$name/main.go; \
				rm -f ./commands/$$name/main.go; \
			else \
				echo "    Skipping - no main.go"; \
			fi; \
		fi; \
	done

# CLI-specific targets.
.PHONY: cli install

cli: ## Build CLI binary.
	go build -o bin/go_hsm ./cmd/go_hsm

install: cli ## Install CLI to GOPATH/bin.
	cp bin/go_hsm $(GOPATH)/bin/

