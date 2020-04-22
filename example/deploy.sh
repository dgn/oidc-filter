#!/bin/bash

kind create cluster || echo cluster already exists
istioctl manifest apply -y

kubectl create -f https://raw.githubusercontent.com/keycloak/keycloak-quickstarts/latest/kubernetes-examples/keycloak.yaml
kubectl rollout status deployment/keycloak
./setup-keycloak.sh

kubectl label namespace default istio-injection=enabled
kubectl create cm oidc-filter --from-file=oidc.wasm=../oidc.wasm
kubectl apply -f httpbin.yaml
kubectl apply -f httpbin-gateway.yaml
kubectl apply -f istio-auth.yaml
kubectl apply -f envoyfilter.yaml
