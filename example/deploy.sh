#!/bin/bash

# kind create cluster || echo cluster already exists

# install maistra extension CRD
kubectl apply -f extensions.maistra.io_servicemeshextensions.yaml

istioctl manifest apply -y -f istio.yaml
# patch cluster role
kubectl apply -f patched-clusterrole.yaml

kubectl create -n default -f https://raw.githubusercontent.com/keycloak/keycloak-quickstarts/latest/kubernetes-examples/keycloak.yaml
kubectl rollout status -n default deployment/keycloak
source setup-keycloak.sh

kubectl label namespace default istio-injection=enabled || true
kubectl apply -n istio-system -f ../../mec/deploy/mec.yaml # wasm-server.yaml
kubectl rollout status -n istio-system deployment/mec #nginx-deployment
#POD=$(kubectl get pods -lapp=nginx -o jsonpath='{.items[0].metadata.name}')
#kubectl cp ../oidc.wasm  ${POD}:/var/www/oidc.wasm --container nginx

kubectl apply -n default -f httpbin.yaml
kubectl apply -n default -f httpbin-gateway.yaml
kubectl rollout status -n default  deployment/httpbin

kubectl apply -n default  -f istio-auth.yaml
sed -e "s/INSERT_CLIENT_SECRET_HERE/${CLIENT_SECRET}/" extension.yaml | kubectl apply -n default  -f -
