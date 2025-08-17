# Authentication Tests

This directory contains comprehensive tests for the MCP server's JWT-based authentication system.

## Test Files

### `authentication_security.rs`
Comprehensive security testing for OAuth2/JWT authentication including:

#### JWT Token Validation
- Valid token acceptance with proper signature
- Invalid token rejection (expired, malformed, wrong signature)
- Token expiration handling
- Claims validation (subject, issued-at, expiration)

#### Bearer Token Extraction
- Proper "Bearer token" format parsing
- Case-insensitive "bearer" handling
- Empty token rejection
- Malformed Authorization header handling
- Missing Authorization header handling

#### OAuth2 Flow Testing
- Client authentication with client_id/client_secret
- Token exchange simulation
- Refresh token handling (if implemented)
- Scope validation

#### Security Protections
- Origin header validation
- DNS rebinding attack prevention
- CSRF protection mechanisms
- Rate limiting validation

## Test Utilities

### `AuthTestHelper`
Provides utilities for authentication testing:
- JWT token generation with configurable expiration
- Test key pair management (RSA/HMAC)
- OAuth2 client credential simulation
- Token validation helpers

### Key Methods
- `generate_valid_jwt()` - Creates valid tokens for testing
- `generate_expired_jwt()` - Creates expired tokens
- `generate_malformed_jwt()` - Creates invalid tokens
- `simulate_oauth_flow()` - Tests complete auth flow

## Test Scenarios

### Positive Cases
- Valid JWT token with proper claims → 200 OK
- Fresh token within expiration → Authentication success
- Proper Bearer token format → Token extracted correctly
- Valid client credentials → Authentication flow success

### Negative Cases
- Expired JWT token → 401 Unauthorized
- Malformed JWT token → 401 Unauthorized
- Missing Authorization header → 401 Unauthorized
- Invalid Bearer format → 401 Unauthorized
- Wrong signature/key → 401 Unauthorized

### Edge Cases
- Token at exact expiration timestamp
- Very long tokens (payload size limits)
- Unicode characters in token claims
- Concurrent authentication requests
- Token with extra/missing claims

## Security Testing

### Attack Prevention
- **Token Replay**: Ensure expired tokens cannot be reused
- **Token Forgery**: Verify signature validation prevents forged tokens
- **DNS Rebinding**: Test origin header validation
- **CSRF**: Verify state parameter handling (if applicable)

### Environment Testing
- Development mode fallback behavior
- Production PKI certificate validation
- Certificate rotation handling
- CA certificate unavailability

## Integration with Cluster PKI

### Certificate Validation
- Tests against real cluster CA certificate (`/etc/ssl/certs/goldentooth.pem`)
- Fallback validation when CA unavailable
- Certificate parsing and key extraction
- RSA/ECDSA signature algorithm support

### Development vs Production
- Development mode: Relaxed validation for testing
- Production mode: Strict PKI validation required
- Environment variable configuration testing
- Security warning validation in development mode

## Running Authentication Tests

### Full Test Suite
```bash
cargo test auth::
```

### Specific Test Categories
```bash
# JWT validation tests
cargo test auth::test_jwt_validation

# Bearer token extraction tests
cargo test auth::test_bearer_extraction

# OAuth flow tests
cargo test auth::test_oauth_flow

# Security protection tests
cargo test auth::test_security_protections
```

### With Real Cluster (Integration)
```bash
cargo test auth:: --features integration
```

## Test Data and Fixtures

### JWT Test Tokens
- Valid tokens with various expiration times
- Tokens with different signature algorithms
- Malformed tokens for negative testing
- Tokens with custom claims for validation

### Mock Certificates
- Test CA certificates for validation
- Invalid certificates for error testing
- Expired certificates for rotation testing

## Performance Requirements

Authentication tests verify:
- Token validation completes within 100ms
- Certificate parsing happens at startup, not per-request
- Memory usage remains constant during token validation
- No authentication bypass under load
