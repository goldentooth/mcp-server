//! HTTP Transport Implementation
//!
//! HTTP transport with SSE streaming support for MCP server.
//! Supports environment-based binding and authentication.

use crate::protocol::process_json_request;
use crate::types::McpStreams;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, body::Incoming, header};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::convert::Infallible;
use std::net::SocketAddr;
use tokio::net::TcpListener;

/// HTTP Transport server for MCP
pub struct HttpTransport {
    bind_addr: SocketAddr,
    auth_required: bool,
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
        }
    }

    /// Start the HTTP transport server
    pub async fn start(self) -> Result<SocketAddr, Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        let addr = listener.local_addr()?;
        let auth_required = self.auth_required;

        // Log server startup
        eprintln!("HTTP transport starting on {addr}");

        // Spawn server task
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        let io = TokioIo::new(stream);

                        tokio::spawn(async move {
                            let service = service_fn(move |req| handle_request(req, auth_required));

                            if let Err(err) = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, service)
                                .await
                            {
                                eprintln!("Error serving connection: {err:?}");
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("Error accepting connection: {e:?}");
                        break;
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

    // Read request body
    let body = req.collect().await?.to_bytes();
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
                // TODO: Validate JWT token here
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

/// Validate JWT token (placeholder - would use actual JWT validation)
async fn validate_jwt_token(_token: &str) -> bool {
    // TODO: Implement actual JWT validation
    // For now, accept any non-empty token
    true
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

/// Validate origin header value
fn is_valid_origin(origin: &str) -> bool {
    if origin.is_empty() {
        return false;
    }

    // Parse as URL
    match url::Url::parse(origin) {
        Ok(url) => {
            // Must be HTTP or HTTPS
            if !matches!(url.scheme(), "http" | "https") {
                return false;
            }

            // Reject if path contains suspicious patterns
            if url.path().contains("..") {
                return false;
            }

            // Reject if fragment contains suspicious content
            if let Some(fragment) = url.fragment() {
                if fragment.contains("attacker.com") || fragment.contains("malicious") {
                    return false;
                }
            }

            // Check against allowed domains
            let allowed_domains = ["goldentooth.net", "localhost", "127.0.0.1"];

            if let Some(host) = url.host_str() {
                // Exact match or subdomain of allowed domains
                allowed_domains
                    .iter()
                    .any(|&allowed| host == allowed || host.ends_with(&format!(".{allowed}")))
            } else {
                false
            }
        }
        Err(_) => false,
    }
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
