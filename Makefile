IMAGE ?= registry.gitlab.com/dgrimm/istio/oidc-filter:latest
CONTAINER_CLI ?= docker
TEST_TIMEOUT ?= 300
BIN_DIRECTORY ?= $(shell pwd)/bin

KIND_VERSION=v0.30.0
KUBECTL_VERSION=v1.34.0
ISTIO_VERSION=1.27.0

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
	@cd examples/envoy && PATH=${BIN_DIRECTORY}:${PATH} ./test.sh

test-istio: plugin.wasm
	@echo \#\#\# Testing Istio example...
	@cd examples/istio && PATH=${BIN_DIRECTORY}:${PATH} ./test.sh

test-envoy-interactive: plugin.wasm
	@echo \#\#\# Running Envoy example interactively...
	@cd examples/envoy && PATH=${BIN_DIRECTORY}:${PATH} ./test.sh --interactive

test-istio-interactive: plugin.wasm
	@echo \#\#\# Running Istio example interactively...
	@cd examples/istio && PATH=${BIN_DIRECTORY}:${PATH} ./test.sh --interactive

test-deps:
	@mkdir -p ${BIN_DIRECTORY}
	@printf "Downloading kind ${KIND_VERSION}...\t"
	@curl -Lo ${BIN_DIRECTORY}/kind https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-linux-amd64 2>/dev/null
	@chmod +x ${BIN_DIRECTORY}/kind
	@echo "✓"
	@printf "Downloading kubectl ${KUBECTL_VERSION}...\t"
	@curl -Lo ${BIN_DIRECTORY}/kubectl "https://cdn.dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" 2>/dev/null
	@chmod +x ${BIN_DIRECTORY}/kubectl
	@echo "✓"
	@printf "Downloading istioctl v${ISTIO_VERSION}...\t"
	@curl -Lo istioctl.tar.gz https://github.com/istio/istio/releases/download/${ISTIO_VERSION}/istioctl-${ISTIO_VERSION}-linux-amd64.tar.gz 2>/dev/null
	@tar xzf istioctl.tar.gz -C ${BIN_DIRECTORY}
	@rm istioctl.tar.gz
	@echo "✓"

lint:
	@cargo fmt -- --check
	@cargo clippy --target wasm32-unknown-unknown -- -D warnings

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
