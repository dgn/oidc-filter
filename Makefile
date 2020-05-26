build: oidc.wasm

oidc.wasm:
	GOPATH=${GOPATH}:${PWD} tinygo build -o oidc.wasm -wasm-abi=generic -target wasm main

.PHONY: clean
clean:
	rm oidc.wasm || true
