#!/bin/bash

# Configuration
AUTHELIA_URL="https://auth.services.goldentooth.net"
MCP_SERVER_URL="http://localhost:8085"
CLIENT_ID="goldentooth-mcp"
CLIENT_SECRET="changeme"

# Step 1: Get access token
echo "Authenticating with Authelia..."
TOKEN_RESPONSE=$(curl -s -X POST "$AUTHELIA_URL/api/oidc/token" \
  -d "grant_type=client_credentials&scope=profile email&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET")

# Extract token using sed instead of python
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')

if [ -z "$ACCESS_TOKEN" ]; then
  echo "Failed to get access token"
  echo "Response: $TOKEN_RESPONSE"
  exit 1
fi

echo "Successfully authenticated!"
echo "Access token: ${ACCESS_TOKEN:0:30}..."

# Step 2: Make MCP request to get server info
echo -e "\nGetting server information..."
SERVER_INFO=$(curl -s -X POST "$MCP_SERVER_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "server/get_info",
    "id": 1
  }')

echo "Server response:"
echo "$SERVER_INFO"

# Step 3: Try listing tools
echo -e "\nListing available tools..."
TOOLS_RESPONSE=$(curl -s -X POST "$MCP_SERVER_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/list",
    "id": 2
  }')

echo "Tools response:"
echo "$TOOLS_RESPONSE"
