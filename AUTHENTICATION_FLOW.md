# Goldentooth MCP Server Authentication Flow

## Technical Documentation: Complete OAuth 2.0 + OpenID Connect Authentication Process

This document provides a comprehensive technical overview of the authentication flow between Claude Code and the Goldentooth MCP Server, detailing every step, protocol, algorithm, and security mechanism involved.

## Table of Contents

1. [Overview](#overview)
2. [Architecture Components](#architecture-components)
3. [Authentication Flow Steps](#authentication-flow-steps)
4. [Security Protocols and Standards](#security-protocols-and-standards)
5. [Token Types and Validation](#token-types-and-validation)
6. [Network Communication](#network-communication)
7. [Error Handling](#error-handling)
8. [Security Considerations](#security-considerations)

## Overview

The Goldentooth MCP Server implements OAuth 2.0 Authorization Code flow with PKCE (Proof Key for Code Exchange) and OpenID Connect for secure authentication with Claude Code. The system uses Authelia as the OAuth 2.0 Authorization Server and OpenID Connect Provider.

### High-Level Flow

```
Claude Code → OAuth Discovery → Authelia (Auth) → MCP Server → Goldentooth Cluster
```

## Architecture Components

### 1. Claude Code (OAuth Client)
- **Role**: OAuth 2.0 Client
- **Implementation**: Node.js application using undici HTTP client
- **Location**: User's local machine
- **Capabilities**: OAuth 2.0 Authorization Code flow with PKCE

### 2. Goldentooth MCP Server (Resource Server)
- **Role**: OAuth 2.0 Resource Server + MCP Protocol Server
- **Implementation**: Rust application using Hyper HTTP server
- **Location**: Goldentooth cluster (multiple Raspberry Pi nodes)
- **Port**: 8085 (internal), 443 (external via reverse proxy)
- **Protocols**: HTTP/1.1, TLS 1.3, MCP (Model Context Protocol)

### 3. Authelia (Authorization Server)
- **Role**: OAuth 2.0 Authorization Server + OpenID Connect Provider
- **Implementation**: Go application
- **Location**: `https://auth.services.goldentooth.net`
- **Standards**: RFC 6749 (OAuth 2.0), RFC 7636 (PKCE), OpenID Connect Core 1.0

### 4. Reverse Proxy/Load Balancer
- **Implementation**: Traefik or similar
- **Location**: Goldentooth cluster edge
- **Domain**: `https://mcp.services.goldentooth.net`
- **TLS**: Certificate signed by Goldentooth internal CA

## Authentication Flow Steps

### Phase 1: OAuth Discovery (RFC 8414)

#### Step 1.1: Claude Code Discovery Request
```http
GET /.well-known/oauth-authorization-server HTTP/1.1
Host: mcp.services.goldentooth.net
User-Agent: @anthropic-ai/claude-code
Accept: application/json
```

**Purpose**: Discover OAuth 2.0 Authorization Server metadata
**RFC**: RFC 8414 - OAuth 2.0 Authorization Server Metadata
**Expected Response**: OAuth metadata JSON

#### Step 1.2: MCP Server Discovery Response
```http
HTTP/1.1 200 OK
Content-Type: application/json
Access-Control-Allow-Origin: *

{
  "issuer": "https://auth.services.goldentooth.net",
  "authorization_endpoint": "https://auth.services.goldentooth.net/api/oidc/authorization",
  "token_endpoint": "https://auth.services.goldentooth.net/api/oidc/token",
  "jwks_uri": "https://auth.services.goldentooth.net/jwks.json",
  "response_types_supported": ["code", "id_token", "token"],
  "grant_types_supported": ["authorization_code", "implicit", "client_credentials", "refresh_token"],
  "scopes_supported": ["offline_access", "openid", "profile", "groups", "email"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
  "code_challenge_methods_supported": ["S256", "plain"],
  "service_documentation": "https://docs.goldentooth.net/mcp"
}
```

#### Step 1.3: Claude Code OIDC Discovery Request
```http
GET /.well-known/openid-configuration HTTP/1.1
Host: mcp.services.goldentooth.net
User-Agent: @anthropic-ai/claude-code
Accept: application/json
```

**Purpose**: Discover OpenID Connect Provider configuration
**RFC**: OpenID Connect Discovery 1.0
**Expected Response**: Same as OAuth metadata (unified endpoint)

### Phase 2: Authorization Request (RFC 6749 + RFC 7636)

#### Step 2.1: Claude Code Generates PKCE Parameters
```javascript
// PKCE Code Challenge Generation (RFC 7636)
const codeVerifier = base64url(crypto.randomBytes(32));
const codeChallenge = base64url(crypto.createHash('sha256').update(codeVerifier).digest());
const codeChallengeMethod = "S256";

// CSRF Protection
const state = base64url(crypto.randomBytes(32));
```

**Algorithm**: SHA256 hash of code_verifier, base64url encoded
**Security**: Protects against authorization code interception attacks

#### Step 2.2: Authorization URL Construction
```
https://auth.services.goldentooth.net/api/oidc/authorization?
  response_type=code&
  client_id=goldentooth-mcp&
  state=${state}&
  redirect_uri=https%3A%2F%2Fmcp.services.goldentooth.net%2Fcallback&
  scope=openid+profile+email+groups&
  code_challenge=${codeChallenge}&
  code_challenge_method=S256
```

**Components**:
- `response_type=code`: Authorization Code flow
- `client_id`: Pre-registered OAuth client identifier
- `state`: CSRF protection token
- `redirect_uri`: Callback URL for authorization response
- `scope`: Requested permissions (OpenID Connect scopes)
- `code_challenge`: PKCE challenge derived from code_verifier
- `code_challenge_method=S256`: SHA256 hash method

#### Step 2.3: User Authorization
1. **Browser Redirect**: Claude Code opens authorization URL in user's browser
2. **Authelia Authentication**: User logs in via Authelia (username/password, 2FA, etc.)
3. **Consent Grant**: User authorizes `goldentooth-mcp` client access
4. **Authorization Response**: Browser redirected to callback URL

### Phase 3: Authorization Callback

#### Step 3.1: Authorization Code Response
```
https://mcp.services.goldentooth.net/callback?
  code=authelia_ac_VprxHtqZH-BnIqMexWBKnMUFoTtnPsJCtH_lbwS1ea8.VabfigbbwrE_J3qZUG_ht7y1v0QZsTchfquUpHk0PE0&
  state=${originalState}
```

**Components**:
- `code`: Single-use authorization code (expires in ~10 minutes)
- `state`: Must match the original state parameter (CSRF protection)

#### Step 3.2: MCP Server Callback Handler
```rust
// Rust implementation in http_server.rs
if req.method() == Method::GET && req.uri().path() == "/callback" {
    let query = req.uri().query().unwrap_or("");
    let params = parse_query_parameters(query);

    if let Some(code) = params.get("code") {
        // Display authorization code for manual copy
        let html = generate_callback_html(&code);
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(Full::new(Bytes::from(html)))
            .unwrap());
    }
}
```

**Security**: HTML escaping prevents XSS attacks on authorization code display

### Phase 4: Token Exchange (RFC 6749 Section 4.1.3)

#### Step 4.1: Claude Code Token Exchange Request
```http
POST /auth/token HTTP/1.1
Host: mcp.services.goldentooth.net
Content-Type: application/json
User-Agent: @anthropic-ai/claude-code

{
  "code": "authelia_ac_VprxHtqZH-BnIqMexWBKnMUFoTtnPsJCtH_lbwS1ea8.VabfigbbwrE_J3qZUG_ht7y1v0QZsTchfquUpHk0PE0"
}
```

#### Step 4.2: MCP Server Proxies to Authelia
```http
POST /api/oidc/token HTTP/1.1
Host: auth.services.goldentooth.net
Content-Type: application/x-www-form-urlencoded
Accept: application/json

grant_type=authorization_code&
code=authelia_ac_VprxHtqZH-BnIqMexWBKnMUFoTtnPsJCtH_lbwS1ea8.VabfigbbwrE_J3qZUG_ht7y1v0QZsTchfquUpHk0PE0&
client_id=goldentooth-mcp&
client_secret=3iQ7WrSZR9HiCLUNeECNXrs1xPjMzk%2BbqXiFzfiyFoo%3D&
redirect_uri=https%3A%2F%2Fmcp.services.goldentooth.net%2Fcallback&
code_verifier=${codeVerifier}
```

**Security Features**:
- `code_verifier`: PKCE verification (proves client that initiated auth)
- `client_secret`: Client authentication (pre-shared secret)
- One-time use: Authorization code consumed after single use

#### Step 4.3: Authelia Token Response
```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Cache-Control: no-store
Pragma: no-cache

{
  "access_token": "authelia_at_PjqVx_hQc36upkjlOrFN5pUtjXw141yGh0Slwmp7zmg.kN862RSIiiX32mPDZVsiLLavR3B_jyQ8g2lZJBitE1Y",
  "token_type": "bearer",
  "expires_in": 3599,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImF1dGhlbGlhLWdvbGRlbnRvb3RoIiwidHlwIjoiSldUIn0.eyJhbXIiOlsicHdkIl0sImF0X2hhc2giOiJzcTVhUmNXcFRyM01GSFNZNkREUmFRIiwiYXVkIjpbImdvbGRlbnRvb3RoLW1jcCJdLCJhdXRoX3RpbWUiOjE3NTM0NDgzODQsImF6cCI6ImdvbGRlbnRvb3RoLW1jcCIsImNsaWVudF9pZCI6ImdvbGRlbnRvb3RoLW1jcCIsImVtYWlsIjoiYWRtaW5AZ29sZGVudG9vdGgubmV0IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImV4cCI6MTc1MzQ1OTMwMywiZ3JvdXBzIjpbImFkbWlucyIsInVzZXJzIl0sImlhdCI6MTc1MzQ1NTcwMywiaXNzIjoiaHR0cHM6Ly9hdXRoLnNlcnZpY2VzLmdvbGRlbnRvb3RoLm5ldCIsImp0aSI6IjY4NWI5ZjhhLTk1MmYtNGQ2MC1hYTcwLWRkMDRhM2ZkYmQ0NCIsIm5hbWUiOiJBZG1pbmlzdHJhdG9yIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWRtaW4iLCJzdWIiOiIyYjc3NWNhNC0yN2YyLTQzZGItYTUzMC01MjIzMGFjZTM1YjUifQ.Y16hldxDGFnCrEWfaAFJp6DsBTarbNU8rVIo3ulyGfQEXcdbLt8dUY5QEQOVogE8Nj4dS0s2ImryUHDeJbu2J12jlWKa8u_ApFGxfsrktZamBcqtG9ynpDg4EcYizbXq7zfu25ncB64WIpOu42UmHKkL85uB8gfmQxPBc--g1M5MAWTZJwtFHFxzb74ifF-Oc8PIK92BN1WE0GItbgBO13-kjIyvyGWbJtNvErDXd75DzCt3YLjsT-1VD7RPVuzlXThVcj3fhvXjC0MbBw4uhI3Fkxzlxaex-E-QVtyADvVpS-0WyJDJPHOBhy_SgL-xWFEbw7zl98u7ChLSH6-3iEwLcQ7LNdHuaeaZS32tVAa-lWo-W-TP2fN19Ey28LLbNF5XLpQSG_1Q9bqjAXk8Mr3c8z4EKikyaZk4K-WKb5V-xkffKub2gMJkEBO_FeA_eWze7O4YOGr7kJYVkSiOC5WNmLSGbJLak__n7OP4sJC4txSLE1fYzwSh39p1B8190uGkWSlc8Y7iKqfzh-S3mXUuNnPaEM8DwqTxZDrUyA07mUSOvhZj9qlBVB4b-oZjqsq2x8GASpQQ0ByPz1P7PkUIgdCQrxlPTLLgTFe5p3xukfoN-xnjYfuo2_kcfBGYBONuA44kpPbTXHKm56SDAdQGsazVirY_t4sxstUwn_4",
  "scope": "openid profile email groups"
}
```

#### Step 4.4: MCP Server Returns Token to Claude Code
```http
HTTP/1.1 200 OK
Content-Type: application/json
Access-Control-Allow-Origin: *

{
  "access_token": "authelia_at_PjqVx_hQc36upkjlOrFN5pUtjXw141yGh0Slwmp7zmg.kN862RSIiiX32mPDZVsiLLavR3B_jyQ8g2lZJBitE1Y",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Phase 5: Authenticated MCP Request

#### Step 5.1: Claude Code MCP Request with Bearer Token
```http
POST /mcp/request HTTP/1.1
Host: mcp.services.goldentooth.net
Authorization: Bearer authelia_at_PjqVx_hQc36upkjlOrFN5pUtjXw141yGh0Slwmp7zmg.kN862RSIiiX32mPDZVsiLLavR3B_jyQ8g2lZJBitE1Y
Content-Type: application/json
User-Agent: @anthropic-ai/claude-code

{
  "jsonrpc": "2.0",
  "method": "initialize",
  "params": {
    "protocolVersion": "0.1.0",
    "capabilities": {}
  },
  "id": 1
}
```

#### Step 5.2: MCP Server Token Validation

**Current Implementation (Problematic)**:
```rust
// This fails because access tokens are opaque, not JWTs
fn validate_token(token: &str) -> Result<Claims, AuthError> {
    let header = decode_header(token)?; // Fails - not a JWT
    let validation = Validation::new(Algorithm::RS256);
    let jwks = fetch_jwks().await?;
    let key = find_key(&jwks, &header.kid)?;
    let decoded = decode::<Claims>(token, &key, &validation)?;
    Ok(decoded.claims)
}
```

**Required Implementation (Token Introspection)**:
```rust
async fn validate_token(token: &str) -> Result<Claims, AuthError> {
    // Check if token is a JWT (3 dot-separated parts)
    if token.matches('.').count() == 2 {
        // JWT validation (for ID tokens)
        validate_jwt_token(token).await
    } else {
        // OAuth 2.0 Token Introspection (RFC 7662) for opaque access tokens
        introspect_access_token(token).await
    }
}

async fn introspect_access_token(token: &str) -> Result<Claims, AuthError> {
    let introspection_request = IntrospectionRequest {
        token: token.to_string(),
        client_id: "goldentooth-mcp".to_string(),
        client_secret: self.config.client_secret.clone(),
    };

    let response = self.client
        .post("https://auth.services.goldentooth.net/api/oidc/introspect")
        .form(&introspection_request)
        .send()
        .await?;

    let introspection: IntrospectionResponse = response.json().await?;

    if introspection.active {
        Ok(Claims::from_introspection(introspection))
    } else {
        Err(AuthError::TokenInactive)
    }
}
```

#### Step 5.3: Successful Authentication Response
```http
HTTP/1.1 200 OK
Content-Type: application/json
Access-Control-Allow-Origin: *

{
  "jsonrpc": "2.0",
  "result": {
    "protocolVersion": "0.1.0",
    "capabilities": {},
    "serverInfo": {
      "name": "goldentooth-mcp",
      "version": "0.0.34"
    }
  },
  "id": 1
}
```

## Security Protocols and Standards

### OAuth 2.0 (RFC 6749)
- **Authorization Code Flow**: Most secure OAuth flow for confidential clients
- **PKCE (RFC 7636)**: Protects against authorization code interception
- **State Parameter**: CSRF protection
- **Client Authentication**: Pre-shared secret validation

### OpenID Connect Core 1.0
- **ID Token**: JWT containing user identity claims
- **UserInfo Endpoint**: Additional user profile information
- **Discovery**: Automatic endpoint and capability discovery

### JSON Web Tokens (RFC 7519)
- **Algorithm**: RS256 (RSA Signature with SHA-256)
- **Key ID (kid)**: "authelia-goldentooth"
- **Claims**: Standard + custom claims (groups, email, etc.)

### TLS Security
- **Version**: TLS 1.3
- **Certificate Authority**: Goldentooth Internal CA
- **Key Exchange**: X25519
- **Cipher Suite**: TLS_AES_256_GCM_SHA384

## Token Types and Validation

### Access Token (Opaque)
```
Format: authelia_at_[base64url_data].[base64url_signature]
Example: authelia_at_PjqVx_hQc36upkjlOrFN5pUtjXw141yGh0Slwmp7zmg.kN862RSIiiX32mPDZVsiLLavR3B_jyQ8g2lZJBitE1Y
Validation: OAuth 2.0 Token Introspection (RFC 7662)
Lifetime: 1 hour (3600 seconds)
Purpose: API access authorization
```

### ID Token (JWT)
```
Format: [header].[payload].[signature]
Header: {
  "alg": "RS256",
  "kid": "authelia-goldentooth",
  "typ": "JWT"
}
Payload: {
  "iss": "https://auth.services.goldentooth.net",
  "aud": ["goldentooth-mcp"],
  "sub": "2b775ca4-27f2-43db-a530-52230ace35b5",
  "exp": 1753459303,
  "iat": 1753455703,
  "email": "admin@goldentooth.net",
  "groups": ["admins", "users"],
  "preferred_username": "admin"
}
Validation: JWT signature verification + claims validation
Lifetime: 1 hour (3600 seconds)
Purpose: User identity assertions
```

### JWKS (JSON Web Key Set)
```
URL: https://auth.services.goldentooth.net/jwks.json
Algorithm: RSA (2048-bit)
Key ID: authelia-goldentooth
Usage: Signature verification for ID tokens
Rotation: Automatic (managed by Authelia)
```

## Network Communication

### Internal Communication Flow
```
Claude Code (Local)
    ↓ HTTPS/TLS 1.3
Traefik Reverse Proxy (Goldentooth Edge)
    ↓ HTTP (Internal Network)
MCP Server (Port 8085, Raspberry Pi Nodes)
    ↓ HTTPS/TLS 1.3 (Internal CA)
Authelia (auth.services.goldentooth.net)
```

### DNS Resolution
```
mcp.services.goldentooth.net → 10.4.0.10 (MetalLB LoadBalancer)
auth.services.goldentooth.net → 10.4.0.10 (MetalLB LoadBalancer)
```

### Certificate Chain
```
Root CA: Goldentooth Root CA
    ↓
Intermediate CA: Goldentooth Intermediate CA
    ↓
Server Certificate: *.services.goldentooth.net
    Subject: CN=*.services.goldentooth.net
    Issuer: O=goldentooth; CN=goldentooth Intermediate CA
    Validity: 24 hours (auto-renewal)
```

## Error Handling

### OAuth Errors (RFC 6749 Section 5.2)
```json
{
  "error": "invalid_grant",
  "error_description": "The provided authorization grant is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client."
}
```

### JWT Validation Errors
```json
{
  "error": "Authentication failed: JWT validation failed: InvalidToken"
}
```

### Token Introspection Errors
```json
{
  "active": false,
  "error": "invalid_token",
  "error_description": "The token is expired, malformed, or invalid"
}
```

### MCP Protocol Errors (JSON-RPC 2.0)
```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32600,
    "message": "Invalid Request"
  },
  "id": null
}
```

## Security Considerations

### Threat Model

1. **Authorization Code Interception**: Mitigated by PKCE
2. **CSRF Attacks**: Mitigated by state parameter
3. **Token Theft**: Mitigated by short token lifetime + HTTPS
4. **Man-in-the-Middle**: Mitigated by TLS + certificate pinning
5. **Replay Attacks**: Mitigated by one-time authorization codes
6. **XSS**: Mitigated by HTML escaping in callback handler

### Security Headers
```http
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
X-Frame-Options: DENY
Cache-Control: no-store
Pragma: no-cache
```

### Key Rotation
- **JWKS Keys**: Automatic rotation by Authelia
- **Client Secrets**: Manual rotation via configuration
- **TLS Certificates**: Daily automatic renewal via cert-renewer

### Audit Logging
- All authentication attempts logged to systemd journal
- OAuth token exchanges logged with masked sensitive data
- Failed authentication attempts trigger monitoring alerts

## Current Issue and Resolution

### Problem
The MCP server currently fails to validate Authelia's opaque access tokens because it attempts JWT validation on non-JWT tokens.

### Root Cause
```
Authelia Access Token: authelia_at_[data].[signature] (Opaque, not JWT)
MCP Server Expectation: JWT token with 3 dot-separated parts
Result: JWT parsing failure → "InvalidToken" error
```

### Solution
Implement dual token validation strategy:
1. **JWT Validation**: For ID tokens (user identity)
2. **Token Introspection (RFC 7662)**: For access tokens (API authorization)

### Implementation Required
```rust
async fn validate_token(&self, token: &str) -> AuthResult<Claims> {
    if self.is_jwt_token(token) {
        self.validate_jwt_token(token).await
    } else {
        self.introspect_access_token(token).await
    }
}
```

This change will enable Claude Code to successfully authenticate with the Goldentooth MCP Server using standard OAuth 2.0 access tokens.
