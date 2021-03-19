FROM envoyproxy/envoy-alpine:v1.17-latest

COPY examples/envoy.yaml /etc/envoy/envoy.yaml
COPY oidc.wasm /var/local/lib/wasm-filters/oidc.wasm
