#!/bin/bash

kind create cluster || echo cluster already exists
istioctl manifest apply -y

kubectl create -f https://raw.githubusercontent.com/keycloak/keycloak-quickstarts/latest/kubernetes-examples/keycloak.yaml
kubectl rollout status deployment/keycloak
source setup-keycloak.sh

kubectl label namespace default istio-injection=enabled || true
kubectl apply -f httpbin.yaml
kubectl apply -f httpbin-gateway.yaml

kubectl rollout status deployment/httpbin
HTTPBIN_POD=$(kubectl get pods -lapp=httpbin -o jsonpath='{.items[0].metadata.name}')
kubectl cp ../plugin.wasm  ${HTTPBIN_POD}:/var/local/lib/wasm-filters/plugin.wasm --container istio-proxy

kubectl apply -f istio-auth.yaml
sed -e "s/INSERT_CLIENT_SECRET_HERE/${CLIENT_SECRET}/" envoyfilter.yaml | kubectl apply -f -
