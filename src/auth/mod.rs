//! Authentication module for MCP server
//!
//! This module provides JWT-based authentication for HTTP transport connections.
//! It validates Bearer tokens using the cluster PKI infrastructure.

pub mod bearer;
pub mod jwt;

use bearer::extract_bearer_token;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode, body::Incoming, header};
use jwt::validate_jwt_token;
use serde_json::json;

/// Check authentication for HTTP requests
///
/// Validates the Authorization header and ensures a valid JWT token is present.
/// Returns Ok(()) if authentication succeeds, or an HTTP 401 response if it fails.
///
/// # Authentication Flow
/// 1. Extract Authorization header
/// 2. Parse Bearer token from header
/// 3. Validate JWT token using cluster PKI
/// 4. Return success or 401 Unauthorized error
///
/// # Arguments
/// * `req` - The HTTP request to authenticate
///
/// # Returns
/// * `Ok(())` if authentication succeeds
/// * `Err(Response)` with 401 Unauthorized if authentication fails
pub async fn check_authentication(req: &Request<Incoming>) -> Result<(), Response<Full<Bytes>>> {
    // Check for Authorization header
    if let Some(auth_header) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            // Extract bearer token
            if let Some(token) = extract_bearer_token(auth_str) {
                // Validate JWT token with cluster PKI
                if validate_jwt_token(token).await {
                    return Ok(());
                }
            }
        }
    }

    // Return authentication required error
    let error_response = json!({
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
    });

    Err(Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(error_response.to_string())))
        .unwrap())
}

/// Check if authentication is required based on environment configuration
///
/// Returns true if MCP_AUTH_REQUIRED is not set to "false" or "0".
/// Authentication is required by default for security.
pub fn is_auth_required() -> bool {
    std::env::var("MCP_AUTH_REQUIRED")
        .map(|v| v.to_lowercase() != "false" && v != "0")
        .unwrap_or(true) // Default to requiring auth
}
