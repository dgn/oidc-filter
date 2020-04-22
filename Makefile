build: oidc.wasm

oidc.wasm:
	tinygo build -o oidc.wasm -wasm-abi=generic -target wasm ./main.go

.PHONY: clean
clean:
	rm oidc.wasm || true
