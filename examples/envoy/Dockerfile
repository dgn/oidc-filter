FROM envoyproxy/envoy-alpine:v1.17-latest

COPY examples/envoy/envoy.yaml /etc/envoy/envoy.yaml
COPY plugin.wasm /var/local/lib/wasm-filters/plugin.wasm
