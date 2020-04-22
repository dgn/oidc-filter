#!/bin/bash

set -ex

kubectl port-forward svc/keycloak 8080:8080 &
port_forward_pid=$!

sleep 2

export TKN=$(curl -X POST 'http://localhost:8080/auth/realms/master/protocol/openid-connect/token' \
 -H "Content-Type: application/x-www-form-urlencoded" \
 -d "username=admin" \
 -d 'password=admin' \
 -d 'grant_type=password' \
 -d 'client_id=admin-cli' | jq -r '.access_token')

curl -X POST 'http://localhost:8080/auth/admin/realms/master/clients' \
 -H "authorization: Bearer $TKN" \
 -H "Content-Type: application/json" \
 --data \
 '{
    "id": "test",
    "name": "test",
    "implicitFlowEnabled": true,
    "redirectUris": ["*"]
 }' 


kill -9 $port_forward_pid
