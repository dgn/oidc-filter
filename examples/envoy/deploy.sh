pushd ../..
docker build -f examples/envoy/Dockerfile -t oidc-filter/envoy-example .
docker run -p 10000:10000 oidc-filter/envoy-example:latest
popd
