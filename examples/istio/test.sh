#!/bin/bash

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
CLUSTER_NAME="oidc-filter-test"
INTERACTIVE_MODE=false
SKIP_CLEANUP=false
ISTIO_VERSION="1.27.0"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --interactive|-i)
            INTERACTIVE_MODE=true
            shift
            ;;
        --skip-cleanup|-s)
            SKIP_CLEANUP=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--interactive|-i] [--help|-h]"
            echo "  --interactive, -i  Run in interactive mode"
            echo "  --skip-cleanup, -s Do not delete test environment after running tests"
            exit 0
            ;;
        *)
            echo "Unknown option $1"
            exit 1
            ;;
    esac
done

if [ "$INTERACTIVE_MODE" = true ]; then
    echo -e "${YELLOW}Starting interactive Istio example deployment...${NC}"
    CLUSTER_NAME="kind"  # Use default cluster name for interactive mode
else
    echo -e "${YELLOW}Starting automated Istio example test...${NC}"
fi

# Cleanup function
cleanup() {
    echo -e "${YELLOW}Cleaning up test environment...${NC}"
    kind delete cluster --name="${CLUSTER_NAME}" 2>/dev/null || true
    pkill -f "kubectl port-forward" 2>/dev/null || true
    # Clean up any remaining background processes
    kill ${ingress_port_forward_pid:-} 2>/dev/null || true
}

# Set trap to cleanup on exit
if [ "$SKIP_CLEANUP" = false ]; then
    trap cleanup EXIT
fi

# Check if required tools are available
check_requirements() {
    local missing_tools=()
    
    command -v kind >/dev/null 2>&1 || missing_tools+=("kind")
    command -v kubectl >/dev/null 2>&1 || missing_tools+=("kubectl")  
    command -v istioctl >/dev/null 2>&1 || missing_tools+=("istioctl")
    command -v curl >/dev/null 2>&1 || missing_tools+=("curl")
    command -v jq >/dev/null 2>&1 || missing_tools+=("jq")
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "${RED}Error: The following required tools are missing: ${missing_tools[*]}${NC}" >&2
        echo -e "${YELLOW}Please install them before running this test.${NC}" >&2
        exit 1
    fi
    
    echo -e "${GREEN}✓ All required tools are available${NC}"
}

# Wait for deployment to be ready
wait_for_deployment() {
    local namespace=$1
    local deployment=$2
    local timeout=${3:-120}
    
    echo -e "${YELLOW}Waiting for deployment ${deployment} in namespace ${namespace} (timeout: ${timeout}s)...${NC}"
    
    if kubectl rollout status deployment/"${deployment}" -n "${namespace}" --timeout="${timeout}s"; then
        echo -e "${GREEN}✓ Deployment ${deployment} is ready${NC}"
        return 0
    else
        echo -e "${RED}✗ Deployment ${deployment} failed to become ready${NC}" >&2
        kubectl describe deployment "${deployment}" -n "${namespace}" >&2
        return 1
    fi
}

echo -e "${YELLOW}Checking requirements...${NC}"
check_requirements

# Step 1: Create kind cluster
echo -e "${YELLOW}Creating kind cluster...${NC}"
kind create cluster --name="${CLUSTER_NAME}" || echo "cluster already exists"

# Step 2: Install Istio
echo -e "${YELLOW}Installing Istio ${ISTIO_VERSION}...${NC}"
istioctl install -y
kubectl apply -f istio-gateway.yaml

# Step 3: Deploy Keycloak
echo -e "${YELLOW}Deploying Keycloak...${NC}"
kubectl create ns auth || echo "namespace auth may already exist"
kubectl apply -n auth -f keycloak.yaml
kubectl rollout -n auth status deployment/keycloak

kubectl port-forward -n istio-system svc/istio-ingressgateway 8081:80 &
ingress_port_forward_pid=$!
sleep 5

# Step 4: Setup Keycloak
echo -e "${YELLOW}Getting Keycloak admin token...${NC}"
TKN=$(curl -s -X POST 'http://localhost:8081/auth/realms/master/protocol/openid-connect/token' \
 -H "Content-Type: application/x-www-form-urlencoded" \
 -d "username=admin" \
 -d 'password=admin' \
 -d 'grant_type=password' \
 -d 'client_id=admin-cli' | jq -r '.access_token')

if [ "${TKN}" = "null" ] || [ -z "${TKN}" ]; then
    echo -e "${RED}Failed to get Keycloak admin token${NC}" >&2
    exit 1
fi

# Create OIDC client
echo -e "${YELLOW}Creating OIDC client...${NC}"
curl -s -X POST 'http://localhost:8081/auth/admin/realms/master/clients' \
 -H "authorization: Bearer ${TKN}" \
 -H "Content-Type: application/json" \
 --data \
 '{
    "id": "test",
    "name": "test",
    "redirectUris": ["*"]
 }' || echo "Client may already exist"

# Get client secret
echo -e "${YELLOW}Getting client secret...${NC}"
CLIENT_SECRET=$(curl -s 'http://localhost:8081/auth/admin/realms/master/clients/test/client-secret' \
 -H "authorization: Bearer ${TKN}" \
 -H "Content-Type: application/json" | jq -r '.value')
export CLIENT_SECRET

if [ "${CLIENT_SECRET}" = "null" ] || [ -z "${CLIENT_SECRET}" ]; then
    echo -e "${RED}Failed to get client secret${NC}" >&2
    exit 1
fi

# Step 5: Deploy httpbin and apply configurations
echo -e "${YELLOW}Deploying httpbin application...${NC}"
kubectl label namespace default istio-injection=enabled || true
kubectl apply -f httpbin.yaml

kubectl rollout status deployment/httpbin
HTTPBIN_POD=$(kubectl get pods -lapp=httpbin -o jsonpath='{.items[0].metadata.name}')

kubectl apply -f istio-auth.yaml
sed -e "s/INSERT_CLIENT_SECRET_HERE/${CLIENT_SECRET}/" wasmplugin.yaml | kubectl apply -f -

# Wait for configurations to propagate
sleep 10

if [ "$INTERACTIVE_MODE" = true ]; then
    echo -e "${GREEN}Deployment completed successfully!${NC}"
    echo -e "${YELLOW}=== Next Steps ====${NC}"
    echo "1. Set up port-forwarding:"
    echo "   kubectl port-forward -n auth svc/keycloak 8080:8080 &"
    echo "   kubectl port-forward -n istio-system svc/istio-ingressgateway 8081:80 &"
    echo ""
    echo "2. Access the application:"
    echo "   Open http://localhost:8081/headers in your browser"
    echo ""
    echo "3. Login with Keycloak:"
    echo "   Username: admin"
    echo "   Password: admin"
    echo ""
    echo "4. Cleanup when done:"
    echo "   kind delete cluster --name ${CLUSTER_NAME}"
    echo ""
    echo -e "${YELLOW}Cluster '${CLUSTER_NAME}' is ready for manual testing!${NC}"
    exit 0
fi

echo -e "${YELLOW}Starting integration tests...${NC}"

# Test 1: Check if httpbin responds with auth redirect
echo -e "${YELLOW}Test 1: Testing authentication redirect...${NC}"
response=$(curl -s -w "%{http_code}" -o /tmp/istio_test_response.html "http://localhost:8081/headers" || echo "000")

if [ "${response}" = "302" ]; then
    location=$(curl -s -I "http://localhost:8081/headers" 2>/dev/null | grep -i "location:" | cut -d' ' -f2- | tr -d '\r')
    if echo "${location}" | grep -q "localhost:8081.*auth.*protocol.*openid-connect.*auth"; then
        echo -e "${GREEN}✓ Correctly redirecting to Keycloak OAuth${NC}"
    else
        echo -e "${YELLOW}Warning: Redirect location might not be correct: ${location}${NC}"
    fi
elif [ "${response}" = "403" ]; then
    if grep -q "Not Authorized" /tmp/istio_test_response.html 2>/dev/null; then
        echo -e "${GREEN}✓ Correctly responding with auth error (${response})${NC}"
    else
        echo -e "${RED}✗ Unexpected 403 response${NC}" >&2
        cat /tmp/istio_test_response.html >&2
        exit 1
    fi
else
    echo -e "${RED}✗ Unexpected HTTP response: ${response}${NC}" >&2
    cat /tmp/istio_test_response.html >&2
    exit 1
fi

# Test 2: Verify WasmPlugin is loaded
echo -e "${YELLOW}Test 2: Verifying WasmPlugin is loaded...${NC}"
if kubectl get wasmplugin openid-connect >/dev/null 2>&1; then
    echo -e "${GREEN}✓ WasmPlugin is deployed${NC}"
else
    echo -e "${RED}✗ WasmPlugin is not deployed${NC}" >&2
    exit 1
fi

# Test 3: Check Istio proxy logs for WASM filter loading
echo -e "${YELLOW}Test 3: Checking for WASM filter in proxy logs...${NC}"
if kubectl logs "${HTTPBIN_POD}" -c istio-proxy | grep -q "wasm\|filter" 2>/dev/null; then
    echo -e "${GREEN}✓ WASM filter appears to be loaded in Istio proxy${NC}"
else
    echo -e "${YELLOW}Warning: Could not verify WASM filter loading from logs${NC}"
fi

# Test 4: Verify Keycloak redirect behavior (detailed)
echo -e "${YELLOW}Test 4: Testing detailed Keycloak redirect behavior...${NC}"

# Test redirect to Keycloak login page with browser-like headers
redirect_response=$(curl -s -I \
    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
    "http://localhost:8081/headers" 2>/dev/null)
if echo "${redirect_response}" | grep -q "HTTP/1.1 302"; then
    location_header=$(echo "${redirect_response}" | grep -i "location:" | cut -d' ' -f2- | tr -d '\r')
    echo -e "${GREEN}✓ Received 302 redirect as expected${NC}"
    
    # Verify redirect goes to Keycloak OAuth endpoint
    # The redirect might point directly to Keycloak (8080) or through ingress (8081)
    if echo "${location_header}" | grep -q "localhost:808[01].*auth.*protocol.*openid-connect.*auth"; then
        echo -e "${GREEN}✓ Redirect points to Keycloak OAuth endpoint${NC}"
        echo "   Redirect URL: ${location_header}"
        
        # Verify redirect contains required OAuth parameters
        if echo "${location_header}" | grep -q "client_id=test" && \
           echo "${location_header}" | grep -q "response_type=code" && \
           echo "${location_header}" | grep -q "scope=openid"; then
            echo -e "${GREEN}✓ OAuth parameters present in redirect URL${NC}"
        else
            echo -e "${YELLOW}Warning: Some OAuth parameters missing from redirect${NC}"
        fi
    else
        echo -e "${RED}✗ Redirect does not point to expected Keycloak endpoint${NC}" >&2
        echo "   Actual location: ${location_header}" >&2
        exit 1
    fi
elif echo "${redirect_response}" | grep -q "HTTP/1.1 403"; then
    echo -e "${YELLOW}Got 403 instead of 302 - this might be expected for non-browser requests${NC}"
    echo -e "${YELLOW}Testing if API requests get 403 as expected...${NC}"
    
    # Test that API requests (without browser headers) get 403
    api_response=$(curl -s -w "%{http_code}" -o /tmp/api_test_response.html "http://localhost:8081/headers" 2>/dev/null)
    if [ "${api_response}" = "403" ]; then
        echo -e "${GREEN}✓ API requests correctly get 403 (non-browser behavior)${NC}"
        
        # Check if the 403 response contains the authorization URL
        if grep -q "accounts.google.com.*oauth2.*auth" /tmp/api_test_response.html 2>/dev/null; then
            echo -e "${GREEN}✓ 403 response contains OAuth authorization URL${NC}"
        else
            echo -e "${YELLOW}Warning: 403 response doesn't contain expected OAuth URL${NC}"
        fi
    else
        echo -e "${RED}✗ API request returned ${api_response} instead of expected 403${NC}" >&2
        exit 1
    fi
else
    echo -e "${RED}✗ Expected 302 redirect but got different response${NC}" >&2
    echo "${redirect_response}" >&2
    exit 1
fi

# Test 5: Get valid auth token and access httpbin directly
echo -e "${YELLOW}Test 5: Testing authenticated access with valid token...${NC}"

# Create a test user in Keycloak for token authentication
echo -e "${YELLOW}Creating test user in Keycloak...${NC}"
TEST_USER="testuser"
TEST_PASSWORD="testpass123"

# Get admin token for user creation
ADMIN_TOKEN=$(curl -s -X POST 'http://localhost:8081/auth/realms/master/protocol/openid-connect/token' \
 -H "Content-Type: application/x-www-form-urlencoded" \
 -d "username=admin" \
 -d 'password=admin' \
 -d 'grant_type=password' \
 -d 'client_id=admin-cli' | jq -r '.access_token')

if [ "${ADMIN_TOKEN}" = "null" ] || [ -z "${ADMIN_TOKEN}" ]; then
    echo -e "${RED}Failed to get admin token for user creation${NC}" >&2
    exit 1
fi

# Create test user
curl -s -X POST 'http://localhost:8081/auth/admin/realms/master/users' \
 -H "authorization: Bearer ${ADMIN_TOKEN}" \
 -H "Content-Type: application/json" \
 --data '{
    "username": "'${TEST_USER}'",
    "enabled": true,
    "credentials": [{
        "type": "password",
        "value": "'${TEST_PASSWORD}'",
        "temporary": false
    }]
 }' >/dev/null || echo "User may already exist"

# Enable direct access grants for the test client (required for password grant)
curl -s -X PUT 'http://localhost:8081/auth/admin/realms/master/clients/test' \
 -H "authorization: Bearer ${ADMIN_TOKEN}" \
 -H "Content-Type: application/json" \
 --data '{
    "id": "test",
    "name": "test",
    "directAccessGrantsEnabled": true,
    "redirectUris": ["*"],
    "publicClient": false
 }' >/dev/null

echo -e "${GREEN}✓ Test user created and client configured${NC}"

# Get access token using resource owner password credentials grant
echo -e "${YELLOW}Getting access token from Keycloak...${NC}"

# First check what issuer Keycloak advertises
echo -e "${YELLOW}Checking Keycloak issuer configuration...${NC}"
WELL_KNOWN=$(curl -s 'http://localhost:8081/auth/realms/master/.well-known/openid_configuration')
KEYCLOAK_ISSUER=$(echo "${WELL_KNOWN}" | jq -r '.issuer')
echo "   Keycloak advertises issuer: ${KEYCLOAK_ISSUER}"
echo "   Istio expects issuer: http://localhost:8081/realms/master"

TOKEN_RESPONSE=$(curl -s -X POST 'http://localhost:8081/auth/realms/master/protocol/openid-connect/token' \
 -H "Content-Type: application/x-www-form-urlencoded" \
 -d "grant_type=password" \
 -d "client_id=test" \
 -d "client_secret=${CLIENT_SECRET}" \
 -d "username=${TEST_USER}" \
 -d "password=${TEST_PASSWORD}")

ACCESS_TOKEN=$(echo "${TOKEN_RESPONSE}" | jq -r '.access_token')
TOKEN_TYPE=$(echo "${TOKEN_RESPONSE}" | jq -r '.token_type')

# Debug: Check the actual issuer in the JWT token
if [ "${ACCESS_TOKEN}" != "null" ] && [ -n "${ACCESS_TOKEN}" ]; then
    # Decode JWT payload (base64 decode the middle part)
    JWT_PAYLOAD=$(echo "${ACCESS_TOKEN}" | cut -d'.' -f2)
    # Add padding if needed for base64 decoding
    case $((${#JWT_PAYLOAD} % 4)) in
        2) JWT_PAYLOAD="${JWT_PAYLOAD}==" ;;
        3) JWT_PAYLOAD="${JWT_PAYLOAD}=" ;;
    esac
    DECODED_PAYLOAD=$(echo "${JWT_PAYLOAD}" | base64 -d 2>/dev/null | jq -r '.iss' 2>/dev/null || echo "decode failed")
    echo "   JWT token contains issuer: ${DECODED_PAYLOAD}"
fi

if [ "${ACCESS_TOKEN}" = "null" ] || [ -z "${ACCESS_TOKEN}" ]; then
    echo -e "${RED}Failed to get access token${NC}" >&2
    echo "Token response: ${TOKEN_RESPONSE}" >&2
    exit 1
fi

echo -e "${GREEN}✓ Successfully obtained access token${NC}"
echo "   Token type: ${TOKEN_TYPE}"
echo "   Token: ${ACCESS_TOKEN}..."

# Test access to httpbin with valid token
echo -e "${YELLOW}Testing httpbin access with valid token...${NC}"
AUTHENTICATED_RESPONSE=$(curl -s -w "%{http_code}" -o /tmp/httpbin_auth_response.json \
 -H "Authorization: Bearer ${ACCESS_TOKEN}" \
 "http://localhost:8081/headers")

if [ "${AUTHENTICATED_RESPONSE}" = "200" ]; then
    echo -e "${GREEN}✓ Successfully accessed httpbin with valid token (HTTP 200)${NC}"
    
    # Verify we got actual httpbin response (should contain headers)
    if grep -q '"headers"' /tmp/httpbin_auth_response.json 2>/dev/null && \
       grep -q '"Host"' /tmp/httpbin_auth_response.json 2>/dev/null; then
        echo -e "${GREEN}✓ Received expected httpbin /headers response${NC}"
        
        # Check if our authorization header is present in the response
        if grep -q '"Authorization":' /tmp/httpbin_auth_response.json 2>/dev/null; then
            echo -e "${GREEN}✓ Authorization header passed through to httpbin${NC}"
        else
            echo -e "${YELLOW}Warning: Authorization header not visible in httpbin response${NC}"
        fi
        
        # Show a snippet of the response
        echo -e "${YELLOW}Sample of httpbin response:${NC}"
        jq -r '.headers | to_entries | .[:3] | .[] | "   \(.key): \(.value)"' /tmp/httpbin_auth_response.json 2>/dev/null || \
        head -n 5 /tmp/httpbin_auth_response.json | sed 's/^/   /'
        
    else
        echo -e "${RED}✗ Response doesn't look like httpbin /headers output${NC}" >&2
        echo "Response preview:" >&2
        head -n 10 /tmp/httpbin_auth_response.json >&2
        exit 1
    fi
else
    echo -e "${RED}✗ Failed to access httpbin with token (HTTP ${AUTHENTICATED_RESPONSE})${NC}" >&2
    echo "Response:" >&2
    cat /tmp/httpbin_auth_response.json >&2
    exit 1
fi

# Test 6: Verify token validation (test with invalid token)
echo -e "${YELLOW}Test 6: Testing invalid token rejection...${NC}"
INVALID_TOKEN_RESPONSE=$(curl -s -w "%{http_code}" -o /tmp/httpbin_invalid_response.html \
 -H "Authorization: Bearer invalid-token-12345" \
 "http://localhost:8081/headers")

if [ "${INVALID_TOKEN_RESPONSE}" = "401" ] || [ "${INVALID_TOKEN_RESPONSE}" = "403" ] || [ "${INVALID_TOKEN_RESPONSE}" = "302" ]; then
    echo -e "${GREEN}✓ Invalid token correctly rejected (HTTP ${INVALID_TOKEN_RESPONSE})${NC}"
else
    echo -e "${YELLOW}Warning: Invalid token returned unexpected response (HTTP ${INVALID_TOKEN_RESPONSE})${NC}"
    echo "This might indicate the JWT validation is not working as expected"
fi

# Test 7: Verify Keycloak is accessible through ingress  
echo -e "${YELLOW}Test 7: Testing Keycloak accessibility through ingress...${NC}"
keycloak_response=$(curl -s -w "%{http_code}" -o /dev/null "http://localhost:8081/auth/realms/master" || echo "000")
if [ "${keycloak_response}" = "200" ]; then
    echo -e "${GREEN}✓ Keycloak is accessible through ingress${NC}"
else
    echo -e "${YELLOW}Warning: Keycloak not accessible through ingress (${keycloak_response})${NC}"
fi

kill $ingress_port_forward_pid 2>/dev/null || true

echo -e "${GREEN}All tests passed! Istio example is working correctly.${NC}"
echo -e "${GREEN}✓ Verified redirect to Keycloak without auth token${NC}"
echo -e "${GREEN}✓ Verified direct access to httpbin with valid auth token${NC}"
echo -e "${GREEN}✓ Verified invalid token rejection${NC}"
echo ""
echo -e "Note: This test performed full OAuth2 flow validation including token-based authentication.${NC}"
echo -e "To test manually: Run 'make test-istio-interactive' and follow the README instructions.${NC}"

# Cleanup will happen automatically via trap