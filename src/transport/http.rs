//! HTTP Transport Implementation
//!
//! HTTP transport with SSE streaming support for MCP server.
//! Supports environment-based binding and authentication.

use crate::protocol::process_json_request;
use crate::types::McpStreams;
use chrono;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, body::Incoming, header};
use hyper_util::rt::TokioIo;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpListener;

/// Configuration constants
const MAX_CONNECTIONS: usize = 100;
const MAX_PAYLOAD_SIZE: usize = 1024 * 1024; // 1MB
const CONNECTION_TIMEOUT_SECS: u64 = 30;

/// JWT Claims structure
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
}

/// Connection guard for automatic connection count management
struct ConnectionGuard {
    connection_count: Arc<AtomicUsize>,
}

impl ConnectionGuard {
    fn new(connection_count: Arc<AtomicUsize>) -> Self {
        Self { connection_count }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.connection_count.fetch_sub(1, Ordering::Relaxed);
    }
}

/// HTTP Transport server for MCP
pub struct HttpTransport {
    bind_addr: SocketAddr,
    auth_required: bool,
    connection_count: Arc<AtomicUsize>,
}

impl HttpTransport {
    /// Create a new HTTP transport
    pub fn new(auth_required: bool) -> Self {
        // Determine binding address based on MCP_LOCAL environment variable
        let bind_addr = if std::env::var("MCP_LOCAL").is_ok_and(|v| !v.is_empty()) {
            "127.0.0.1:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };

        Self {
            bind_addr,
            auth_required,
            connection_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Start the HTTP transport server
    pub async fn start(self) -> Result<SocketAddr, Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        let addr = listener.local_addr()?;
        let auth_required = self.auth_required;
        let connection_count = self.connection_count.clone();

        // Log server startup
        eprintln!("HTTP transport starting on {addr}");

        // Spawn server task
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        // Check connection limit
                        let current_connections = connection_count.load(Ordering::Relaxed);
                        if current_connections >= MAX_CONNECTIONS {
                            eprintln!(
                                "Connection limit reached ({MAX_CONNECTIONS}), rejecting connection"
                            );
                            continue;
                        }

                        // Increment connection count
                        connection_count.fetch_add(1, Ordering::Relaxed);
                        let conn_count = connection_count.clone();

                        let io = TokioIo::new(stream);

                        tokio::spawn(async move {
                            // Ensure connection count is decremented when task ends
                            let _guard = ConnectionGuard::new(conn_count);

                            let service = service_fn(move |req| handle_request(req, auth_required));

                            // Set connection timeout
                            let connection_fut = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, service);

                            let timeout_duration =
                                std::time::Duration::from_secs(CONNECTION_TIMEOUT_SECS);

                            match tokio::time::timeout(timeout_duration, connection_fut).await {
                                Ok(connection_result) => {
                                    if let Err(err) = connection_result {
                                        eprintln!("Error serving connection: {err:?}");
                                    }
                                }
                                Err(_) => {
                                    eprintln!(
                                        "Connection timed out after {CONNECTION_TIMEOUT_SECS}s"
                                    );
                                }
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("Error accepting connection: {e:?}");
                        // Continue accepting connections instead of breaking
                        continue;
                    }
                }
            }
        });

        Ok(addr)
    }
}

/// Handle incoming HTTP requests
async fn handle_request(
    req: Request<Incoming>,
    auth_required: bool,
) -> Result<Response<Full<Bytes>>, Infallible> {
    match handle_request_inner(req, auth_required).await {
        Ok(response) => Ok(response),
        Err(e) => {
            eprintln!("Error handling request: {e:?}");
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from("Internal Server Error")))
                .unwrap())
        }
    }
}

/// Inner request handler that can return errors
async fn handle_request_inner(
    req: Request<Incoming>,
    auth_required: bool,
) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    let method = req.method();
    let path = req.uri().path();

    // Only handle /mcp endpoint
    if path != "/mcp" {
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("Not Found")))
            .unwrap());
    }

    // Authentication check (if required)
    if auth_required {
        if let Err(auth_response) = check_authentication(&req).await {
            return Ok(auth_response);
        }
    }

    // Origin header validation for security
    if let Err(origin_response) = validate_origin_header(&req) {
        return Ok(origin_response);
    }

    match *method {
        Method::POST => handle_post_request(req).await,
        Method::GET => {
            // Check if this is an SSE connection request
            if is_sse_request(&req) {
                handle_sse_request(req).await
            } else {
                Ok(Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Full::new(Bytes::from("Method Not Allowed")))
                    .unwrap())
            }
        }
        _ => Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Full::new(Bytes::from("Method Not Allowed")))
            .unwrap()),
    }
}

/// Handle POST requests (JSON-RPC over HTTP)
async fn handle_post_request(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    // Check if client accepts SSE response
    let accept_sse = req
        .headers()
        .get(header::ACCEPT)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.contains("text/event-stream"))
        .unwrap_or(false);

    // Read request body with size limit
    let body = req.collect().await?.to_bytes();

    // Check payload size limit
    if body.len() > MAX_PAYLOAD_SIZE {
        return Ok(Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {
                    "code": -32003,
                    "message": "Payload too large",
                    "data": {
                        "type": "PayloadError",
                        "details": format!("Request body exceeds maximum size of {} bytes", MAX_PAYLOAD_SIZE)
                    }
                }
            }).to_string())))?);
    }

    let json_str = String::from_utf8(body.to_vec())?;

    // Process MCP request
    let mut streams = McpStreams::new();
    let response = process_json_request(&json_str, &mut streams).await?;

    if accept_sse {
        // Return SSE formatted response
        let response_json = response.to_json_string()?;
        let sse_data = format!("data: {response_json}\n\n");

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/event-stream")
            .header("Cache-Control", "no-cache")
            .header("Connection", "close") // Close after single response
            .header("Access-Control-Allow-Origin", "*")
            .body(Full::new(Bytes::from(sse_data)))?)
    } else {
        // Return regular JSON response
        let response_json = response.to_json_string()?;

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(response_json)))?)
    }
}

/// Handle SSE connection requests (GET with Accept: text/event-stream)
async fn handle_sse_request(
    _req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    // For now, we don't support persistent SSE connections
    // All SSE responses are delivered via POST requests and closed immediately
    Ok(Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(
            "SSE connections via GET not supported. Use POST with Accept: text/event-stream",
        )))?)
}

/// Check if request is asking for SSE response
fn is_sse_request(req: &Request<Incoming>) -> bool {
    req.headers()
        .get(header::ACCEPT)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.contains("text/event-stream"))
        .unwrap_or(false)
}

/// Check authentication (placeholder - would integrate with actual auth system)
async fn check_authentication(req: &Request<Incoming>) -> Result<(), Response<Full<Bytes>>> {
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

/// Extract bearer token from Authorization header
fn extract_bearer_token(auth_header: &str) -> Option<&str> {
    if auth_header.to_lowercase().starts_with("bearer ") {
        let token = auth_header[7..].trim_start();
        if token.is_empty() { None } else { Some(token) }
    } else {
        None
    }
}

/// Validate JWT token using cluster PKI
async fn validate_jwt_token(token: &str) -> bool {
    // Get cluster CA certificate for JWT validation
    let ca_cert_path = "/etc/ssl/certs/goldentooth.pem";

    // Try to read the public key from cluster CA
    let public_key = match std::fs::read(ca_cert_path) {
        Ok(cert_data) => {
            // For now, use a simple approach - in production, extract public key from cert
            match DecodingKey::from_rsa_pem(&cert_data) {
                Ok(key) => Some(key),
                Err(_) => {
                    eprintln!("Failed to parse cluster CA certificate for JWT validation");
                    None
                }
            }
        }
        Err(_) => {
            // Fallback: use a default validation approach for development
            eprintln!("Cluster CA certificate not found, using fallback validation");
            None
        }
    };

    // If we have a public key, validate with it; otherwise use fallback
    if let Some(key) = public_key {
        // Validate token with cluster CA
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;

        match decode::<Claims>(token, &key, &validation) {
            Ok(token_data) => {
                // Additional validation: check subject and expiration
                let now = chrono::Utc::now().timestamp() as usize;
                !token_data.claims.sub.is_empty() && token_data.claims.exp > now
            }
            Err(err) => {
                eprintln!("JWT validation failed: {err:?}");
                false
            }
        }
    } else {
        // Fallback validation for development
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return false;
        }

        // Try to decode without signature verification (development only)
        let mut validation = Validation::new(Algorithm::RS256);
        validation.insecure_disable_signature_validation();
        validation.validate_exp = true;

        match decode::<Claims>(token, &DecodingKey::from_secret(&[]), &validation) {
            Ok(token_data) => {
                // Check expiration
                let now = chrono::Utc::now().timestamp() as usize;
                token_data.claims.exp > now
            }
            Err(_) => false,
        }
    }
}

/// Validate Origin header to prevent DNS rebinding attacks
#[allow(clippy::result_large_err)]
fn validate_origin_header(req: &Request<Incoming>) -> Result<(), Response<Full<Bytes>>> {
    if let Some(origin_header) = req.headers().get("Origin") {
        if let Ok(origin_str) = origin_header.to_str() {
            if !is_valid_origin(origin_str) {
                let error_response = json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {
                        "code": -32002,
                        "message": "Invalid origin",
                        "data": {
                            "type": "SecurityError",
                            "details": "Origin header validation failed"
                        }
                    }
                });

                return Err(Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(error_response.to_string())))
                    .unwrap());
            }
        }
    }

    Ok(())
}

/// Validate origin header value with robust security checks
fn is_valid_origin(origin: &str) -> bool {
    if origin.is_empty() {
        return false;
    }

    // Parse as URL
    let url = match url::Url::parse(origin) {
        Ok(url) => url,
        Err(_) => return false,
    };

    // Must be HTTP or HTTPS
    if !matches!(url.scheme(), "http" | "https") {
        return false;
    }

    // Reject suspicious paths
    let path = url.path();
    if path.contains("..") || path.contains("//") || path.contains("%2e") || path.contains("%2f") {
        return false;
    }

    // Reject suspicious query parameters
    if let Some(query) = url.query() {
        let suspicious_patterns = ["javascript:", "data:", "vbscript:", "file:", "about:"];
        for pattern in &suspicious_patterns {
            if query.to_lowercase().contains(pattern) {
                return false;
            }
        }
    }

    // Reject suspicious fragments
    if let Some(fragment) = url.fragment() {
        let suspicious_patterns = ["javascript:", "data:", "vbscript:", "file:", "about:"];
        for pattern in &suspicious_patterns {
            if fragment.to_lowercase().contains(pattern) {
                return false;
            }
        }
    }

    // Get host and normalize
    let host = match url.host_str() {
        Some(host) => host.to_lowercase(),
        None => return false,
    };

    // Reject IP addresses that are not explicitly allowed
    if host.parse::<std::net::Ipv4Addr>().is_ok() || host.parse::<std::net::Ipv6Addr>().is_ok() {
        return matches!(host.as_str(), "127.0.0.1" | "::1" | "localhost");
    }

    // Check against allowed domains with strict validation
    let allowed_domains = ["goldentooth.net", "localhost"];

    for &allowed in &allowed_domains {
        // Exact match
        if host == allowed {
            return true;
        }
        // Subdomain match (must have dot separator)
        let subdomain_pattern = format!(".{allowed}");
        if host.ends_with(&subdomain_pattern) {
            // Ensure it's actually a subdomain, not just a suffix
            let prefix = &host[..host.len() - subdomain_pattern.len()];
            if !prefix.is_empty()
                && !prefix.contains('.')
                && prefix.chars().all(|c| c.is_alphanumeric() || c == '-')
            {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, sleep};

    #[tokio::test]
    async fn test_http_transport_creation() {
        let _transport = HttpTransport::new(false);

        // Should use localhost binding if MCP_LOCAL is set
        unsafe {
            std::env::set_var("MCP_LOCAL", "1");
        }
        let local_transport = HttpTransport::new(false);
        assert!(local_transport.bind_addr.ip().is_loopback());

        // Should use any interface if MCP_LOCAL is not set
        unsafe {
            std::env::remove_var("MCP_LOCAL");
        }
        let any_transport = HttpTransport::new(false);
        assert!(any_transport.bind_addr.ip().is_unspecified());
    }

    #[tokio::test]
    async fn test_bearer_token_extraction() {
        assert_eq!(
            extract_bearer_token("Bearer test-token"),
            Some("test-token")
        );
        assert_eq!(extract_bearer_token("bearer lowercase"), Some("lowercase"));
        assert_eq!(extract_bearer_token("Bearer "), None);
        assert_eq!(extract_bearer_token("Basic auth"), None);
        assert_eq!(extract_bearer_token(""), None);
    }

    #[tokio::test]
    async fn test_origin_validation() {
        // Valid origins
        assert!(is_valid_origin("https://goldentooth.net"));
        assert!(is_valid_origin("https://app.goldentooth.net"));
        assert!(is_valid_origin("http://localhost:3000"));
        assert!(is_valid_origin("http://127.0.0.1:8080"));

        // Invalid origins
        assert!(!is_valid_origin("javascript:alert(1)"));
        assert!(!is_valid_origin("https://attacker.com"));
        assert!(!is_valid_origin("https://goldentooth.net.evil.com"));
        assert!(!is_valid_origin(""));
        assert!(!is_valid_origin("malicious.com"));
    }

    #[tokio::test]
    async fn test_http_transport_startup() {
        let transport = HttpTransport::new(false);
        let addr = transport
            .start()
            .await
            .expect("Should start HTTP transport");

        // Should bind to a port
        assert!(addr.port() > 0);

        // Give server time to start
        sleep(Duration::from_millis(10)).await;

        // TODO: Test actual HTTP requests once server is running
    }
}
