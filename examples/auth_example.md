# MCP Server Authentication Example

This example shows how to authenticate with the Goldentooth MCP server and make requests.

## 1. Get an OAuth2 Access Token

First, obtain an access token from Authelia using the client credentials grant:

```bash
# Request a token
TOKEN_RESPONSE=$(curl -s -X POST https://auth.services.goldentooth.net/api/oidc/token \
  -d "grant_type=client_credentials&scope=profile email&client_id=goldentooth-mcp&client_secret=changeme")

# Extract the access token
ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
echo "Access token: $ACCESS_TOKEN"
```

## 2. Make an Authenticated Request to the MCP Server

The MCP server uses JSON-RPC over HTTP. Here's how to make a request:

```bash
# Make a JSON-RPC request to get server info
curl -X POST http://localhost:8085 \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "server/get_info",
    "id": 1
  }'
```

## 3. Example MCP Protocol Requests

### Get Server Information
```bash
curl -X POST http://localhost:8085 \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "server/get_info",
    "id": 1
  }'
```

### List Available Tools
```bash
curl -X POST http://localhost:8085 \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/list",
    "id": 2
  }'
```

### Execute a Tool
```bash
curl -X POST http://localhost:8085 \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/execute",
    "params": {
      "name": "get_cluster_status",
      "arguments": {}
    },
    "id": 3
  }'
```

## 4. Complete Example Script

```bash
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

ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")

if [ -z "$ACCESS_TOKEN" ]; then
  echo "Failed to get access token"
  echo "Response: $TOKEN_RESPONSE"
  exit 1
fi

echo "Successfully authenticated!"
echo "Access token: ${ACCESS_TOKEN:0:20}..."

# Step 2: Make MCP request
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
echo $SERVER_INFO | python3 -m json.tool
```

## 5. Token Introspection

You can verify your token is valid:

```bash
curl -X POST https://auth.services.goldentooth.net/api/oidc/introspection \
  -d "token=$ACCESS_TOKEN&client_id=goldentooth-mcp&client_secret=changeme" | python3 -m json.tool
```

## Notes

- Tokens expire after 1 hour (3600 seconds)
- The MCP server validates tokens on each request
- If authentication fails, you'll receive a 401 Unauthorized response
- The server falls back to no authentication if the OAuth configuration fails
