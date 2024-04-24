IMAGE ?= registry.gitlab.com/dgrimm/istio/oidc-filter:latest
CONTAINER_CLI ?= docker

build: clean plugin.wasm

plugin.wasm:
	@echo \#\#\# Building wasm module...
	@cargo build --target wasm32-unknown-unknown --release
	@cp target/wasm32-unknown-unknown/release/oidc_filter.wasm ./plugin.wasm

image: plugin.wasm
	@echo \#\#\# Building container...
	@${CONTAINER_CLI} build -f container/Dockerfile . -t ${IMAGE}

.PHONY: clean
clean:
	@echo \#\#\# Cleaning up...
	@rm plugin.wasm || true
	rm -r build || true
