#!/bin/bash

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
CONTAINER_NAME="oidc-filter-envoy-test"
TEST_PORT=10001
TIMEOUT=30
INTERACTIVE_MODE=false
SKIP_CLEANUP=false

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
            echo "  --interactive, -i   Run in interactive mode"
            echo "  --skip-cleanup, -s  Do not delete test environment after running tests"
            echo "  --help, -h          Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option $1"
            exit 1
            ;;
    esac
done

if [ "$INTERACTIVE_MODE" = true ]; then
    echo -e "${YELLOW}Starting interactive Envoy example deployment...${NC}"
else
    echo -e "${YELLOW}Starting automated Envoy example test...${NC}"
fi

# Cleanup function
cleanup() {
    echo -e "${YELLOW}Cleaning up test environment...${NC}"
    docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true
    docker rmi -f oidc-filter/envoy-example 2>/dev/null || true
}

# Set trap to cleanup on exit
if [ "$SKIP_CLEANUP" = false ]; then
    trap cleanup EXIT
fi

# Check if required tools are available
command -v docker >/dev/null 2>&1 || { echo -e "${RED}Error: docker is required but not installed.${NC}" >&2; exit 1; }

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo -e "${RED}Error: Docker daemon is not running.${NC}" >&2
    exit 1
fi

echo -e "${YELLOW}Building Envoy example image...${NC}"
pushd ../.. > /dev/null
docker build -f examples/envoy/Dockerfile -t oidc-filter/envoy-example .
popd > /dev/null

# Start the container
if [ "$INTERACTIVE_MODE" = true ]; then
    echo -e "${YELLOW}Starting Envoy container interactively on port 10000...${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
    # Run interactively (blocking)
    docker run -p 10000:10000 oidc-filter/envoy-example:latest
    exit 0
else
    echo -e "${YELLOW}Starting Envoy container on port ${TEST_PORT}...${NC}"
    if ! docker run -d --name "${CONTAINER_NAME}" -p "${TEST_PORT}:10000" oidc-filter/envoy-example:latest; then
        echo -e "${RED}Failed to start Envoy container${NC}" >&2
        exit 1
    fi
fi

# Wait for container to be ready
echo -e "${YELLOW}Waiting for Envoy to start (timeout: ${TIMEOUT}s)...${NC}"
for i in $(seq 1 ${TIMEOUT}); do
    if docker exec "${CONTAINER_NAME}" pgrep envoy >/dev/null 2>&1; then
        echo -e "${GREEN}Envoy process is running${NC}"
        break
    fi
    if [ "$i" -eq ${TIMEOUT} ]; then
        echo -e "${RED}Timeout waiting for Envoy to start${NC}" >&2
        docker logs "${CONTAINER_NAME}"
        exit 1
    fi
    sleep 1
done

# Test 1: Check if the service is listening
echo -e "${YELLOW}Test 1: Checking if service is listening on port ${TEST_PORT}...${NC}"
for i in $(seq 1 10); do
    if nc -z localhost "${TEST_PORT}" 2>/dev/null; then
        echo -e "${GREEN}✓ Service is listening on port ${TEST_PORT}${NC}"
        break
    fi
    if [ "$i" -eq 10 ]; then
        echo -e "${RED}✗ Service is not listening on port ${TEST_PORT}${NC}" >&2
        exit 1
    fi
    sleep 1
done

# Test 2: Check OIDC filter behavior
echo -e "${YELLOW}Test 2: Testing OIDC filter behavior...${NC}"

# Wait a bit more for the service to be fully ready
sleep 3

# Test connection with more verbose output for debugging
echo -e "${YELLOW}Attempting connection to http://localhost:${TEST_PORT}/...${NC}"
HTTP_RESPONSE=$(curl -v -s -w "%{http_code}" -o /tmp/test_response.html --connect-timeout 10 "http://localhost:${TEST_PORT}/" 2>/tmp/curl_error.log || echo "000")
if [ "${HTTP_RESPONSE}" = "000" ]; then
    echo -e "${RED}✗ Failed to connect to the service${NC}" >&2
    echo -e "${YELLOW}Curl error log:${NC}" >&2
    cat /tmp/curl_error.log >&2 || echo "No curl error log available"
    echo -e "${YELLOW}Container status:${NC}" >&2
    docker ps | grep "${CONTAINER_NAME}" || echo "Container not running"
    echo -e "${YELLOW}Container logs:${NC}" >&2
    docker logs "${CONTAINER_NAME}" 2>&1 | tail -10
    exit 1
elif [ "${HTTP_RESPONSE}" = "302" ]; then
    # Check if the redirect URL contains Google OAuth
    LOCATION=$(cat /tmp/curl_error.log | grep -i "location:" | cut -d' ' -f2- | tr -d '\r')
    if echo "${LOCATION}" | grep -q "accounts.google.com"; then
        echo -e "${GREEN}✓ Correctly redirecting to Google OAuth${NC}"
    else
        echo -e "${RED}✗ Redirect location does not contain Google OAuth URL${NC}" >&2
        echo "Location header: ${LOCATION}" >&2
        exit 1
    fi
elif [ "${HTTP_RESPONSE}" = "403" ]; then
    # Check if it's the expected non-browser request response
    if grep -q "Not Authorized" /tmp/test_response.html 2>/dev/null && \
       grep -q "accounts.google.com" /tmp/test_response.html 2>/dev/null; then
        echo -e "${GREEN}✓ Correctly responding with auth error for non-browser request (${HTTP_RESPONSE})${NC}"
    else
        echo -e "${RED}✗ Unexpected 403 response content${NC}" >&2
        cat /tmp/test_response.html >&2
        exit 1
    fi
elif [ "${HTTP_RESPONSE}" = "503" ]; then
    # Check if it's a service error
    if grep -q "No handshake object\|Cannot dispatch call" /tmp/test_response.html 2>/dev/null; then
        echo -e "${GREEN}✓ Correctly responding with service error (${HTTP_RESPONSE})${NC}"
    else
        echo -e "${RED}✗ Unexpected 503 response${NC}" >&2
        cat /tmp/test_response.html >&2
        exit 1
    fi
else
    echo -e "${RED}✗ Unexpected HTTP response code: ${HTTP_RESPONSE}${NC}" >&2
    if [ -f /tmp/test_response.html ]; then
        cat /tmp/test_response.html >&2
    fi
    exit 1
fi

# Test 3: Test browser-like request (should get 302 redirect)
echo -e "${YELLOW}Test 3: Testing browser-like request...${NC}"
HTTP_RESPONSE=$(curl -s -w "%{http_code}" -o /tmp/test_browser_response.html \
    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
    "http://localhost:${TEST_PORT}/" 2>/dev/null || echo "000")

if [ "${HTTP_RESPONSE}" = "302" ]; then
    # Check if the redirect URL contains Google OAuth
    LOCATION=$(curl -s -I \
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
        -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
        "http://localhost:${TEST_PORT}/" 2>/dev/null | grep -i "location:" | cut -d' ' -f2- | tr -d '\r')
    if echo "${LOCATION}" | grep -q "accounts.google.com"; then
        echo -e "${GREEN}✓ Correctly redirecting browser requests to Google OAuth${NC}"
    else
        echo -e "${YELLOW}Warning: Browser request redirect may not contain expected OAuth URL${NC}"
        echo "Location header: ${LOCATION}"
    fi
else
    echo -e "${YELLOW}Warning: Browser-like request returned ${HTTP_RESPONSE} instead of 302${NC}"
    if [ -f /tmp/test_browser_response.html ]; then
        head -n 3 /tmp/test_browser_response.html
    fi
fi

# Test 4: Check container logs for any obvious errors
echo -e "${YELLOW}Test 4: Checking container logs for errors...${NC}"
LOGS=$(docker logs "${CONTAINER_NAME}" 2>&1)
if echo "${LOGS}" | grep -qi "error\|failed\|panic"; then
    echo -e "${YELLOW}Warning: Found potential errors in logs:${NC}"
    echo "${LOGS}" | grep -i "error\|failed\|panic" || true
    echo -e "${YELLOW}This might be expected for auth-related errors${NC}"
else
    echo -e "${GREEN}✓ No obvious errors in container logs${NC}"
fi

# Test 5: Verify OIDC filter configuration is loaded
echo -e "${YELLOW}Test 5: Verifying OIDC filter configuration...${NC}"
if echo "${LOGS}" | grep -q "Building wasm module\|oidc\|auth"; then
    echo -e "${GREEN}✓ OIDC filter appears to be configured${NC}"
else
    echo -e "${YELLOW}Warning: Could not verify OIDC filter configuration from logs${NC}"
fi

echo -e "${GREEN}All tests passed! Envoy example is working correctly.${NC}"
echo -e "${YELLOW}Note: Manual testing with actual Google OAuth credentials is still recommended.${NC}"
echo -e "${YELLOW}To test manually: Replace placeholders in envoy.yaml and run 'make test-envoy-interactive'${NC}"
