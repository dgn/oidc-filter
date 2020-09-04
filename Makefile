build: oidc.wasm

oidc.wasm:
	cargo build --target wasm32-unknown-unknown --release
	cp target/wasm32-unknown-unknown/release/oidc_filter.wasm ./oidc.wasm

.PHONY: clean
clean:
	rm oidc.wasm || true
	rm -r build || true

.PHONY: container
container: clean build
	mkdir build
	cp container/manifest.yaml build/
	cp oidc.wasm build/
	cd build && podman build -t oidc-filter . -f ../container/Dockerfile
