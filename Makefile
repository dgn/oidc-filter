IMAGE ?= registry.gitlab.com/dgrimm/istio/oidc-filter:latest
CONTAINER_CLI ?= docker
TEST_TIMEOUT ?= 300

build: clean plugin.wasm

plugin.wasm:
	@echo \#\#\# Building wasm module...
	@cargo build --target wasm32-unknown-unknown --release
	@cp target/wasm32-unknown-unknown/release/oidc_filter.wasm ./plugin.wasm

image: plugin.wasm
	@echo \#\#\# Building container...
	@${CONTAINER_CLI} build -f container/Dockerfile . -t ${IMAGE}

# Test targets
test: build test-envoy test-istio
	@echo \#\#\# All tests passed!

test-envoy: plugin.wasm
	@echo \#\#\# Testing Envoy example...
	@cd examples/envoy && ./test.sh

test-istio: plugin.wasm
	@echo \#\#\# Testing Istio example...
	@cd examples/istio && ./test.sh

test-envoy-interactive: plugin.wasm
	@echo \#\#\# Running Envoy example interactively...
	@cd examples/envoy && ./test.sh --interactive

test-istio-interactive: plugin.wasm
	@echo \#\#\# Running Istio example interactively...
	@cd examples/istio && ./test.sh --interactive

.PHONY: clean clean-test test test-envoy test-istio test-envoy-interactive test-istio-interactive
clean:
	@echo \#\#\# Cleaning up...
	@rm plugin.wasm || true
	@rm -r build || true

clean-test:
	@echo \#\#\# Cleaning up test environment...
	@${CONTAINER_CLI} rm -f oidc-filter-envoy-test || true
	@${CONTAINER_CLI} rmi -f oidc-filter/envoy-example || true
	@kind delete cluster || true
