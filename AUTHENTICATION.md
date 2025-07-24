# MCP Server Authentication with Authelia

This document describes how to configure and use the Goldentooth MCP server with Authelia OIDC authentication.

## Overview

The MCP server supports optional authentication via Authelia's OpenID Connect (OIDC) provider. When enabled, all MCP requests must include a valid JWT token obtained through the OAuth2 flow.

## Configuration

### Environment Variables

Set the following environment variables to enable authentication:

```bash
# Required for authentication
OAUTH_CLIENT_SECRET=your-actual-client-secret-here

# Optional (have sensible defaults)
OAUTH_CLIENT_ID=goldentooth-mcp
AUTHELIA_BASE_URL=https://auth.goldentooth.net:9091
OAUTH_REDIRECT_URI=https://mcp.goldentooth.net/callback
```

### Authelia Configuration

The Authelia server should already be configured with an OIDC client for the MCP server:

- **Client ID**: `goldentooth-mcp`
- **Scopes**: `openid`, `profile`, `email`, `groups`, `offline_access`
- **Grant Types**: `authorization_code`, `refresh_token`
- **Redirect URI**: `https://mcp.goldentooth.net/callback`

## Authentication Flow

### 1. Authorization Code Flow

```bash
# Get authorization URL
curl -X POST http://localhost:8080/auth/authorize

# Example response:
{
  "authorization_url": "https://auth.goldentooth.net:9091/api/oidc/authorization?client_id=goldentooth-mcp&...",
  "csrf_token": "random-csrf-token"
}
```

### 2. User Authentication

1. Redirect user to the authorization URL
2. User authenticates with Authelia (username/password + optional MFA)
3. Authelia redirects back to the redirect URI with an authorization code

### 3. Token Exchange

```bash
# Exchange authorization code for access token
curl -X POST http://localhost:8080/auth/token \
  -H "Content-Type: application/json" \
  -d '{"code": "authorization-code-from-callback"}'

# Example response:
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### 4. Making Authenticated Requests

Include the access token in the Authorization header:

```bash
curl -X POST http://localhost:8080/mcp/request \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{"method": "some_mcp_method", "params": {}}'
```

## Token Validation

The MCP server validates JWT tokens by:

1. **Signature Verification**: Using Authelia's public keys from JWKS endpoint
2. **Claims Validation**: Checking issuer, audience, and expiration
3. **Scope Verification**: Ensuring required scopes are present

## Deployment with Ansible

The MCP server authentication is automatically configured when deployed via Ansible:

```bash
# Deploy MCP server with authentication
goldentooth setup_mcp_server
```

The Ansible role configures the systemd service with the appropriate environment variables from the vault.

## Testing Authentication

### Test without Authentication

```bash
# Should work without auth header
cargo run --example test_auth
```

### Test with Authentication Enabled

```bash
# Should attempt to connect to Authelia
OAUTH_CLIENT_SECRET=real-secret cargo run --example test_auth
```

### Test Token Validation

```bash
# Validate a specific JWT token
TEST_JWT_TOKEN=your-jwt-token-here OAUTH_CLIENT_SECRET=real-secret cargo run --example test_auth
```

## Security Considerations

### Token Security

- **Secure Storage**: Store access tokens securely in the client
- **HTTPS Only**: Always use HTTPS for token transmission
- **Token Expiration**: Implement proper token refresh logic
- **Scope Limitation**: Request only necessary scopes

### Service Configuration

- **Client Secret**: Keep the OAuth client secret secure and rotate regularly
- **TLS**: Ensure all communication with Authelia uses TLS
- **Network Security**: Restrict network access between services

## Troubleshooting

### Common Issues

1. **DNS Resolution**: Ensure `auth.goldentooth.net` resolves correctly
2. **Certificate Issues**: Verify TLS certificates are valid
3. **Clock Skew**: Ensure system clocks are synchronized
4. **Network Connectivity**: Check firewall rules and network routing

### Debug Mode

Enable debug logging for more detailed error information:

```bash
RUST_LOG=debug cargo run --example test_auth
```

### Authentication Disabled

If `OAUTH_CLIENT_SECRET` is not set or equals "changeme", authentication is disabled and all requests are allowed without tokens.

## API Endpoints

When authentication is enabled, the MCP server exposes additional endpoints:

- `GET /auth/info` - OIDC configuration information
- `POST /auth/authorize` - Get authorization URL
- `POST /auth/token` - Exchange authorization code for token
- `POST /auth/refresh` - Refresh access token

## Integration with MCP Clients

MCP clients should implement the OAuth2 authorization code flow:

1. **Initial Setup**: Register with the authorization server
2. **User Authentication**: Redirect to authorization URL
3. **Token Management**: Store and refresh tokens as needed
4. **Request Authentication**: Include Bearer token in all requests

## User Management

Users are managed in Authelia's user database:

- **Admin User**: Full cluster access
- **Service Users**: Programmatic access with limited scopes
- **Regular Users**: Read-only access to appropriate resources

See the Authelia documentation for user management details.
