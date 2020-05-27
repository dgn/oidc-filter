build: oidc.wasm

oidc.wasm:
	cargo build --target wasm32-unknown-unknown --release
	cp target/wasm32-unknown-unknown/release/oidc_filter.wasm ./oidc.wasm

.PHONY: clean
clean:
	rm oidc.wasm || true
