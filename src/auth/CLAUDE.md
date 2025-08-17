# Authentication Module

This module handles JWT-based authentication for the MCP server's HTTP transport.

## Overview

The authentication system validates Bearer tokens using the cluster's PKI infrastructure, specifically the cluster CA certificate located at `/etc/ssl/certs/goldentooth.pem`.

## Module Structure

```
auth/
├── CLAUDE.md           # This documentation
├── mod.rs              # Main authentication interface
├── jwt.rs              # JWT token validation logic
└── bearer.rs           # Bearer token extraction from headers
```

## Key Components

### `mod.rs` - Main Interface
- `check_authentication()` - Main authentication function called by HTTP transport
- `is_auth_required()` - Checks if authentication is enabled via environment variables

### `jwt.rs` - JWT Validation
- `validate_jwt_token()` - Validates JWT tokens using cluster CA certificate
- `Claims` struct - JWT token claims structure (sub, exp, iat)
- Supports both production PKI validation and development fallback mode

### `bearer.rs` - Token Extraction
- `extract_bearer_token()` - Extracts Bearer tokens from Authorization headers
- Handles case-insensitive "Bearer" prefix
- Validates token format and emptiness

## Authentication Flow

1. HTTP request arrives at `/mcp` endpoint
2. `check_authentication()` is called if `auth_required` is true
3. Authorization header is extracted from request
4. Bearer token is parsed from "Bearer <token>" format
5. JWT token is validated against cluster CA certificate
6. Success returns `Ok(())`, failure returns HTTP 401 response

## Environment Variables

- `MCP_AUTH_REQUIRED` - Set to "false" or "0" to disable authentication (default: enabled)

## Error Responses

Authentication failures return JSON-RPC error responses:
```json
{
    "jsonrpc": "2.0",
    "id": null,
    "error": {
        "code": -32001,
        "message": "Authentication required",
        "data": {
            "type": "AuthenticationError",
            "details": "HTTP transport requires valid JWT token"
        }
    }
}
```

## Security Features

- **PKI Integration**: Uses cluster CA certificate for JWT validation
- **Development Fallback**: Insecure validation mode when CA cert unavailable
- **Token Expiration**: Validates JWT expiration timestamps
- **Header Validation**: Proper Bearer token format checking
- **Origin Validation**: Works with transport-level origin header checks

## Usage

```rust
use crate::auth::check_authentication;

// In HTTP transport handler
if auth_required {
    if let Err(auth_response) = check_authentication(&req).await {
        return Ok(auth_response); // Return 401 error
    }
}
```

## Testing

The module includes comprehensive tests for:
- Bearer token extraction with various formats
- JWT validation with valid/invalid tokens
- Environment variable configuration
- Error response formatting
