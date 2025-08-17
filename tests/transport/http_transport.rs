//! HTTP Transport Tests
//!
//! Tests for HTTP transport functionality including server lifecycle,
//! endpoint availability, environment-based binding, and basic request/response.

use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::{Value, json};
use std::env;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::timeout;

use crate::common::test_helpers::{McpRequestBuilders, ResponseAssertions};

/// HTTP Transport test helper with server lifecycle management
pub struct HttpTransportTester {
    server_addr: SocketAddr,
    client: Client<hyper_util::client::legacy::connect::HttpConnector, Full<hyper::body::Bytes>>,
    auth_token: Option<String>,
}

impl HttpTransportTester {
    /// Create a new HTTP transport tester
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Find available port for test server
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let server_addr = listener.local_addr()?;
        drop(listener); // Release the port for the actual server to use

        let client = Client::builder(TokioExecutor::new()).build_http();

        Ok(Self {
            server_addr,
            client,
            auth_token: None,
        })
    }

    /// Set authentication token for requests
    pub fn with_auth_token(mut self, token: String) -> Self {
        self.auth_token = Some(token);
        self
    }

    /// Get the base URL for the test server
    pub fn base_url(&self) -> String {
        format!("http://{}", self.server_addr)
    }

    /// Get the MCP endpoint URL
    pub fn mcp_endpoint_url(&self) -> String {
        format!("{}/mcp", self.base_url())
    }

    /// Send a JSON-RPC request to the MCP endpoint
    pub async fn send_jsonrpc_request(
        &self,
        request: Value,
    ) -> Result<hyper::Response<hyper::body::Incoming>, Box<dyn std::error::Error>> {
        let json_body = request.to_string();
        let mut req_builder = Request::builder()
            .method(Method::POST)
            .uri(self.mcp_endpoint_url())
            .header("Content-Type", "application/json")
            .header("Content-Length", json_body.len());

        if let Some(ref token) = self.auth_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {token}"));
        }

        let request = req_builder.body(Full::new(hyper::body::Bytes::from(json_body)))?;
        Ok(self.client.request(request).await?)
    }

    /// Send request and parse JSON response
    pub async fn send_and_parse_response(
        &self,
        request: Value,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let response = self.send_jsonrpc_request(request).await?;
        let body_bytes = response.into_body().collect().await?.to_bytes();
        let body_str = String::from_utf8(body_bytes.to_vec())?;
        Ok(serde_json::from_str(&body_str)?)
    }

    /// Check if server is responding on the MCP endpoint
    pub async fn is_server_responding(&self) -> bool {
        let ping_request = McpRequestBuilders::ping(1).build();
        match timeout(
            Duration::from_secs(1),
            self.send_jsonrpc_request(ping_request),
        )
        .await
        {
            Ok(Ok(response)) => response.status() != StatusCode::NOT_FOUND,
            _ => false,
        }
    }
}

/// Mock HTTP server for testing binding behavior
pub struct MockHttpServer {
    addr: SocketAddr,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl MockHttpServer {
    /// Start a mock server on the specified address
    pub async fn start(addr: SocketAddr) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(addr).await?;
        let actual_addr = listener.local_addr()?;

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        // Spawn server task
        tokio::spawn(async move {
            let mut shutdown_rx = shutdown_rx;
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept_result = listener.accept() => {
                        if let Ok((stream, _)) = accept_result {
                            // Simple echo server for testing
                            tokio::spawn(async move {
                                let _ = stream;
                                // Server is just checking if port is bindable
                            });
                        }
                    }
                }
            }
        });

        Ok(Self {
            addr: actual_addr,
            shutdown_tx: Some(shutdown_tx),
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for MockHttpServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

#[tokio::test]
async fn test_http_transport_tester_creation() {
    let _tester = HttpTransportTester::new()
        .await
        .expect("Should create tester");
    assert!(_tester.base_url().starts_with("http://127.0.0.1:"));
    assert!(_tester.mcp_endpoint_url().ends_with("/mcp"));
}

#[tokio::test]
async fn test_mcp_endpoint_url_format() {
    let tester = HttpTransportTester::new()
        .await
        .expect("Should create tester");
    let mcp_url = tester.mcp_endpoint_url();

    // Verify URL format
    assert!(mcp_url.starts_with("http://127.0.0.1:"));
    assert!(mcp_url.ends_with("/mcp"));

    // Verify it's a valid URL
    let parsed = url::Url::parse(&mcp_url).expect("Should be valid URL");
    assert_eq!(parsed.path(), "/mcp");
}

#[tokio::test]
async fn test_jsonrpc_request_building() {
    let _tester = HttpTransportTester::new()
        .await
        .expect("Should create tester");

    let ping_request = McpRequestBuilders::ping(1).build();
    assert_eq!(ping_request["method"], "ping");
    assert_eq!(ping_request["id"], 1);
    assert_eq!(ping_request["jsonrpc"], "2.0");

    // Verify request can be serialized for HTTP
    let json_str = ping_request.to_string();
    assert!(json_str.contains("\"method\":\"ping\""));
    assert!(json_str.contains("\"id\":1"));
}

#[tokio::test]
async fn test_auth_token_handling() {
    let _tester = HttpTransportTester::new()
        .await
        .expect("Should create tester")
        .with_auth_token("test-token-123".to_string());

    // Verify token is stored
    assert!(_tester.auth_token.is_some());
    assert_eq!(_tester.auth_token.unwrap(), "test-token-123");
}

// Environment variable binding tests
#[tokio::test]
async fn test_binding_behavior_setup() {
    // Test that we can control environment variables for binding tests
    unsafe {
        env::set_var("TEST_MCP_LOCAL", "1");
    }
    assert_eq!(env::var("TEST_MCP_LOCAL").unwrap(), "1");

    unsafe {
        env::remove_var("TEST_MCP_LOCAL");
    }
    assert!(env::var("TEST_MCP_LOCAL").is_err());
}

#[tokio::test]
async fn test_server_address_selection() {
    // Test different address selection based on environment

    // Test local binding preference
    let local_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = TcpListener::bind(local_addr)
        .await
        .expect("Should bind to localhost");
    let bound_addr = listener.local_addr().expect("Should get bound address");
    assert!(bound_addr.ip().is_loopback());
    drop(listener);

    // Test any address binding
    let any_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let listener = TcpListener::bind(any_addr)
        .await
        .expect("Should bind to any interface");
    let bound_addr = listener.local_addr().expect("Should get bound address");
    assert!(bound_addr.ip().is_unspecified());
    drop(listener);
}

#[tokio::test]
async fn test_mock_server_lifecycle() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = MockHttpServer::start(addr)
        .await
        .expect("Should start mock server");

    let bound_addr = server.addr();
    assert!(bound_addr.port() > 0);

    // Verify server is listening
    let listener_test = TcpListener::bind(bound_addr).await;
    assert!(listener_test.is_err()); // Port should be occupied

    // Server should shutdown when dropped
    drop(server);

    // Give a moment for cleanup
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Port should be available again
    let listener_test = TcpListener::bind(bound_addr).await;
    assert!(listener_test.is_ok()); // Port should be free
}

// Basic HTTP endpoint tests (without actual server implementation yet)
#[tokio::test]
async fn test_http_client_configuration() {
    let _tester = HttpTransportTester::new()
        .await
        .expect("Should create tester");

    // Test that we can create proper HTTP requests
    let ping_request = McpRequestBuilders::ping(42).build();
    let json_body = ping_request.to_string();

    let request = Request::builder()
        .method(Method::POST)
        .uri(_tester.mcp_endpoint_url())
        .header("Content-Type", "application/json")
        .header("Content-Length", json_body.len())
        .body(Full::new(hyper::body::Bytes::from(json_body)))
        .expect("Should build request");

    assert_eq!(request.method(), &Method::POST);
    assert!(request.uri().path().ends_with("/mcp"));
    assert_eq!(
        request.headers().get("Content-Type").unwrap(),
        "application/json"
    );
}

#[tokio::test]
async fn test_request_response_format_validation() {
    // Test JSON-RPC request format compliance
    let initialize_request = McpRequestBuilders::initialize(1).build();

    // Verify required JSON-RPC fields
    assert_eq!(initialize_request["jsonrpc"], "2.0");
    assert!(initialize_request.get("method").is_some());
    assert!(initialize_request.get("id").is_some());
    assert!(initialize_request.get("params").is_some());

    // Verify MCP-specific fields
    assert_eq!(initialize_request["method"], "initialize");
    assert_eq!(
        initialize_request["params"]["protocolVersion"],
        "2025-06-18"
    );
    assert!(initialize_request["params"]["capabilities"].is_object());
    assert!(initialize_request["params"]["clientInfo"].is_object());
}

// Response format validation test
#[tokio::test]
async fn test_expected_response_format() {
    // Test that we can validate expected response format
    let mock_success_response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "capabilities": {},
            "serverInfo": {
                "name": "goldentooth-mcp",
                "version": "0.0.23"
            },
            "protocolVersion": "2025-06-18"
        }
    });

    ResponseAssertions::assert_initialize_response(&mock_success_response, 1);

    let mock_error_response = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "error": {
            "code": -32601,
            "message": "Method not found"
        }
    });

    ResponseAssertions::assert_error_response(&mock_error_response, 2, -32601);
}

// Test that HTTP transport is now implemented
#[tokio::test]
async fn test_http_server_now_implemented() {
    // Start a real HTTP transport
    unsafe {
        std::env::set_var("MCP_AUTH_REQUIRED", "false");
    }
    let transport = goldentooth_mcp::transport::HttpTransport::new(false);
    let addr = transport
        .start()
        .await
        .expect("Should start HTTP transport");

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let _tester = HttpTransportTester::new()
        .await
        .expect("Should create tester");

    // Create client pointing to our actual server
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build_http();

    // Test actual server response
    let ping_request = McpRequestBuilders::ping(1).build();
    let json_body = ping_request.to_string();

    let request = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(format!("http://{addr}/mcp"))
        .header("Content-Type", "application/json")
        .header("Content-Length", json_body.len())
        .body(http_body_util::Full::new(hyper::body::Bytes::from(
            json_body,
        )))
        .expect("Should build request");

    let response =
        tokio::time::timeout(tokio::time::Duration::from_secs(2), client.request(request))
            .await
            .expect("Request should not timeout")
            .expect("Should send request");

    // HTTP transport is now implemented and responding
    assert_eq!(response.status(), hyper::StatusCode::OK);
}
