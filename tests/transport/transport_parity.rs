//! Transport Parity Tests
//!
//! Tests to ensure that HTTP and stdio transports provide identical functionality
//! and behavior as required by Stage 2 specifications.

use goldentooth_mcp::protocol::process_json_request;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::{Value, json};
use std::net::SocketAddr;
use tokio::net::TcpListener;

use crate::common::test_helpers::{
    McpRequestBuilders, McpRequestProcessor, ResponseAssertions, TestStreamsBuilder,
};

/// Transport parity tester that can test both stdio and HTTP transports
pub struct TransportParityTester {
    stdio_processor: McpRequestProcessor,
    http_client: Option<HttpTransportClient>,
}

impl Default for TransportParityTester {
    fn default() -> Self {
        Self::new()
    }
}

impl TransportParityTester {
    /// Create a new transport parity tester
    pub fn new() -> Self {
        let stdio_processor = McpRequestProcessor::new();

        Self {
            stdio_processor,
            http_client: None,
        }
    }

    /// Enable HTTP transport testing (when HTTP server is available)
    pub async fn with_http_transport(
        mut self,
        server_addr: SocketAddr,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        self.http_client = Some(HttpTransportClient::new(server_addr).await?);
        Ok(self)
    }

    /// Process a request via stdio transport
    pub async fn process_stdio(&mut self, request: Value) -> Result<Value, String> {
        self.stdio_processor.process(request).await
    }

    /// Process a request via HTTP transport (if available)
    pub async fn process_http(&self, request: Value) -> Result<Value, Box<dyn std::error::Error>> {
        match &self.http_client {
            Some(client) => client.send_and_parse_response(request).await,
            None => Err("HTTP transport not configured".into()),
        }
    }

    /// Compare responses from both transports for identical behavior
    pub async fn compare_transports(&mut self, request: Value) -> TransportComparisonResult {
        let request_id = request.get("id").cloned();
        let stdio_result = self.process_stdio(request.clone()).await;

        let http_result = if let Some(client) = &self.http_client {
            client
                .send_and_parse_response(request)
                .await
                .map_err(|e| e.to_string())
        } else {
            Err("HTTP transport not available".to_string())
        };

        TransportComparisonResult {
            stdio_result,
            http_result,
            request_id,
        }
    }

    /// Test that both transports handle the same set of MCP methods
    pub async fn test_method_support_parity(&mut self) -> Vec<MethodSupportResult> {
        let test_methods = vec![
            ("initialize", McpRequestBuilders::initialize(1).build()),
            ("ping", McpRequestBuilders::ping(2).build()),
            ("tools/list", McpRequestBuilders::tools_list(3).build()),
            (
                "resources/list",
                McpRequestBuilders::resources_list(4).build(),
            ),
            ("prompts/list", McpRequestBuilders::prompts_list(5).build()),
        ];

        let mut results = Vec::new();

        for (method_name, request) in test_methods {
            let comparison = self.compare_transports(request).await;
            results.push(MethodSupportResult {
                method: method_name.to_string(),
                comparison,
            });
        }

        results
    }
}

/// HTTP transport client for testing
pub struct HttpTransportClient {
    client: Client<hyper_util::client::legacy::connect::HttpConnector, Full<hyper::body::Bytes>>,
    base_url: String,
    auth_token: Option<String>,
}

impl HttpTransportClient {
    pub async fn new(server_addr: SocketAddr) -> Result<Self, Box<dyn std::error::Error>> {
        let client = Client::builder(TokioExecutor::new()).build_http();
        let base_url = format!("http://{server_addr}");

        Ok(Self {
            client,
            base_url,
            auth_token: None,
        })
    }

    pub fn with_auth_token(mut self, token: String) -> Self {
        self.auth_token = Some(token);
        self
    }

    pub async fn send_and_parse_response(
        &self,
        request: Value,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let json_body = request.to_string();
        let mut req_builder = Request::builder()
            .method(Method::POST)
            .uri(format!("{}/mcp", self.base_url))
            .header("Content-Type", "application/json")
            .header("Content-Length", json_body.len());

        if let Some(ref token) = self.auth_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {token}"));
        }

        let request = req_builder.body(Full::new(hyper::body::Bytes::from(json_body)))?;
        let response = self.client.request(request).await?;

        let body_bytes = response.into_body().collect().await?.to_bytes();
        let body_str = String::from_utf8(body_bytes.to_vec())?;
        Ok(serde_json::from_str(&body_str)?)
    }
}

/// Result of comparing responses between transports
#[derive(Debug)]
pub struct TransportComparisonResult {
    pub stdio_result: Result<Value, String>,
    pub http_result: Result<Value, String>,
    pub request_id: Option<Value>,
}

impl TransportComparisonResult {
    /// Check if both transports gave identical successful responses
    pub fn is_identical_success(&self) -> bool {
        match (&self.stdio_result, &self.http_result) {
            (Ok(stdio_response), Ok(http_response)) => stdio_response == http_response,
            _ => false,
        }
    }

    /// Check if both transports gave identical error responses
    pub fn is_identical_error(&self) -> bool {
        match (&self.stdio_result, &self.http_result) {
            (Err(stdio_error), Err(http_error)) => stdio_error == http_error,
            _ => false,
        }
    }

    /// Check if both transports gave the same type of response (success or error)
    pub fn has_same_response_type(&self) -> bool {
        matches!(
            (&self.stdio_result, &self.http_result),
            (Ok(_), Ok(_)) | (Err(_), Err(_))
        )
    }

    /// Get the error code from a response if it's an error
    fn extract_error_code(response: &Value) -> Option<i32> {
        response
            .get("error")?
            .get("code")?
            .as_i64()
            .map(|c| c as i32)
    }

    /// Check if both responses have the same error code (if they are errors)
    pub fn has_same_error_code(&self) -> bool {
        match (&self.stdio_result, &self.http_result) {
            (Ok(stdio_response), Ok(http_response)) => {
                let stdio_code = Self::extract_error_code(stdio_response);
                let http_code = Self::extract_error_code(http_response);
                stdio_code == http_code
            }
            _ => false,
        }
    }
}

/// Result of testing method support across transports
#[derive(Debug)]
pub struct MethodSupportResult {
    pub method: String,
    pub comparison: TransportComparisonResult,
}

impl MethodSupportResult {
    /// Check if this method is supported identically by both transports
    pub fn is_supported_identically(&self) -> bool {
        self.comparison.has_same_response_type()
    }

    /// Get a description of any parity issues
    pub fn parity_issues(&self) -> Vec<String> {
        let mut issues = Vec::new();

        if !self.comparison.has_same_response_type() {
            issues.push(format!(
                "Response type mismatch for method '{}'",
                self.method
            ));
        }

        if !self.comparison.is_identical_success() && !self.comparison.is_identical_error() {
            issues.push(format!(
                "Response content differs for method '{}'",
                self.method
            ));
        }

        issues
    }
}

/// Mock HTTP server that mimics stdio transport behavior
pub struct MockStdioMimicHttpServer {
    addr: SocketAddr,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl MockStdioMimicHttpServer {
    /// Start a mock server that processes requests like stdio transport
    pub async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let mut shutdown_rx = shutdown_rx;
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept_result = listener.accept() => {
                        if let Ok((stream, _)) = accept_result {
                            tokio::spawn(Self::handle_http_like_stdio(stream));
                        }
                    }
                }
            }
        });

        Ok(Self {
            addr,
            shutdown_tx: Some(shutdown_tx),
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Handle HTTP request by processing JSON-RPC like stdio transport
    async fn handle_http_like_stdio(stream: tokio::net::TcpStream) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = stream;
        let mut buffer = [0; 4096];

        if let Ok(n) = stream.read(&mut buffer).await {
            let request = String::from_utf8_lossy(&buffer[..n]);

            // Extract JSON body from HTTP request
            if let Some(body_start) = request.find("\r\n\r\n") {
                let body = &request[body_start + 4..];

                // Process with stdio transport logic
                let mut streams = TestStreamsBuilder::new().capture_output().build();

                if let Ok(response_msg) = process_json_request(body, &mut streams).await {
                    let response_json = response_msg.to_json_string().unwrap();

                    let http_response = format!(
                        "HTTP/1.1 200 OK\r\n\
                         Content-Type: application/json\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\
                         \r\n\
                         {}",
                        response_json.len(),
                        response_json
                    );

                    let _ = stream.write_all(http_response.as_bytes()).await;
                }
            }
        }

        let _ = stream.shutdown().await;
    }
}

impl Drop for MockStdioMimicHttpServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

// Core Parity Tests

#[tokio::test]
async fn test_transport_comparison_result_analysis() {
    // Test successful identical responses
    let success_response = json!({"jsonrpc": "2.0", "id": 1, "result": {}});
    let success_comparison = TransportComparisonResult {
        stdio_result: Ok(success_response.clone()),
        http_result: Ok(success_response),
        request_id: Some(json!(1)),
    };

    assert!(success_comparison.is_identical_success());
    assert!(success_comparison.has_same_response_type());
    assert!(!success_comparison.is_identical_error());

    // Test error responses
    let error_response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": -32601, "message": "Method not found"}
    });

    let error_comparison = TransportComparisonResult {
        stdio_result: Ok(error_response.clone()),
        http_result: Ok(error_response),
        request_id: Some(json!(1)),
    };

    assert!(error_comparison.has_same_error_code());
    assert!(error_comparison.has_same_response_type());

    // Test mismatched responses
    let mismatch_comparison = TransportComparisonResult {
        stdio_result: Ok(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
        http_result: Err("Connection failed".to_string()),
        request_id: Some(json!(1)),
    };

    assert!(!mismatch_comparison.has_same_response_type());
    assert!(!mismatch_comparison.is_identical_success());
}

#[tokio::test]
async fn test_method_support_result_analysis() {
    let success_comparison = TransportComparisonResult {
        stdio_result: Ok(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
        http_result: Ok(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
        request_id: Some(json!(1)),
    };

    let method_result = MethodSupportResult {
        method: "ping".to_string(),
        comparison: success_comparison,
    };

    assert!(method_result.is_supported_identically());
    assert!(method_result.parity_issues().is_empty());

    // Test method with issues
    let mismatch_comparison = TransportComparisonResult {
        stdio_result: Ok(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
        http_result: Err("HTTP transport not available".to_string()),
        request_id: Some(json!(1)),
    };

    let problematic_method = MethodSupportResult {
        method: "problematic".to_string(),
        comparison: mismatch_comparison,
    };

    assert!(!problematic_method.is_supported_identically());
    let issues = problematic_method.parity_issues();
    assert!(!issues.is_empty());
    assert!(
        issues
            .iter()
            .any(|issue| issue.contains("Response type mismatch"))
    );
}

#[tokio::test]
async fn test_transport_parity_tester_creation() {
    let tester = TransportParityTester::new();
    assert!(tester.http_client.is_none()); // HTTP not configured yet

    // Test with mock HTTP server
    let mock_server = MockStdioMimicHttpServer::start()
        .await
        .expect("Should start mock server");
    let tester_with_http = tester
        .with_http_transport(mock_server.addr())
        .await
        .expect("Should configure HTTP transport");

    assert!(tester_with_http.http_client.is_some());
}

#[tokio::test]
async fn test_stdio_transport_processing() {
    let mut tester = TransportParityTester::new();

    // Test basic stdio processing
    let ping_request = McpRequestBuilders::ping(1).build();
    let response = tester
        .process_stdio(ping_request)
        .await
        .expect("Should process stdio request");

    ResponseAssertions::assert_success_response(&response, 1);
}

#[tokio::test]
async fn test_mock_http_server_stdio_mimicking() {
    let mock_server = MockStdioMimicHttpServer::start()
        .await
        .expect("Should start mock server");
    let client = HttpTransportClient::new(mock_server.addr())
        .await
        .expect("Should create client");

    // Send request via HTTP that should be processed like stdio
    let ping_request = McpRequestBuilders::ping(1).build();
    let response = client
        .send_and_parse_response(ping_request)
        .await
        .expect("Should get response from mock server");

    ResponseAssertions::assert_success_response(&response, 1);
}

#[tokio::test]
async fn test_transport_parity_with_mock_server() {
    let mock_server = MockStdioMimicHttpServer::start()
        .await
        .expect("Should start mock server");
    let mut tester = TransportParityTester::new()
        .with_http_transport(mock_server.addr())
        .await
        .expect("Should configure HTTP transport");

    // Test that both transports give identical responses
    let ping_request = McpRequestBuilders::ping(1).build();
    let comparison = tester.compare_transports(ping_request).await;

    assert!(
        comparison.has_same_response_type(),
        "Both transports should succeed"
    );
    assert!(
        comparison.is_identical_success(),
        "Responses should be identical"
    );
}

#[tokio::test]
async fn test_method_support_parity_basic() {
    let mock_server = MockStdioMimicHttpServer::start()
        .await
        .expect("Should start mock server");
    let mut tester = TransportParityTester::new()
        .with_http_transport(mock_server.addr())
        .await
        .expect("Should configure HTTP transport");

    // Test method support across transports
    let method_results = tester.test_method_support_parity().await;

    // All methods should be supported identically
    for result in &method_results {
        assert!(
            result.is_supported_identically(),
            "Method '{}' should be supported identically. Issues: {:?}",
            result.method,
            result.parity_issues()
        );
    }

    // Should test multiple methods
    assert!(method_results.len() >= 3, "Should test multiple methods");

    // Should include core MCP methods
    let method_names: Vec<&str> = method_results.iter().map(|r| r.method.as_str()).collect();
    assert!(method_names.contains(&"initialize"));
    assert!(method_names.contains(&"ping"));
    assert!(method_names.contains(&"tools/list"));
}

#[tokio::test]
async fn test_error_response_parity() {
    let mock_server = MockStdioMimicHttpServer::start()
        .await
        .expect("Should start mock server");
    let mut tester = TransportParityTester::new()
        .with_http_transport(mock_server.addr())
        .await
        .expect("Should configure HTTP transport");

    // Test with invalid method name
    let invalid_request = json!({
        "jsonrpc": "2.0",
        "method": "nonexistent_method",
        "id": 1
    });

    let comparison = tester.compare_transports(invalid_request).await;

    // Both should return errors for invalid methods
    assert!(
        comparison.has_same_response_type(),
        "Both transports should return errors"
    );

    // Error codes should match
    if let (Ok(stdio_response), Ok(http_response)) =
        (&comparison.stdio_result, &comparison.http_result)
    {
        let stdio_code = TransportComparisonResult::extract_error_code(stdio_response);
        let http_code = TransportComparisonResult::extract_error_code(http_response);
        assert_eq!(
            stdio_code, http_code,
            "Error codes should match between transports"
        );
    }
}

#[tokio::test]
async fn test_request_id_handling_parity() {
    let mock_server = MockStdioMimicHttpServer::start()
        .await
        .expect("Should start mock server");
    let mut tester = TransportParityTester::new()
        .with_http_transport(mock_server.addr())
        .await
        .expect("Should configure HTTP transport");

    // Test different ID types
    let test_cases = vec![
        (json!(42), "number ID"),
        (json!("test-string-id"), "string ID"),
        (json!(null), "null ID"),
    ];

    for (id, description) in test_cases {
        let request = json!({
            "jsonrpc": "2.0",
            "method": "ping",
            "id": id.clone()
        });

        let comparison = tester.compare_transports(request).await;

        assert!(
            comparison.has_same_response_type(),
            "Both transports should handle {description}"
        );

        if let (Ok(stdio_response), Ok(http_response)) =
            (&comparison.stdio_result, &comparison.http_result)
        {
            assert_eq!(
                stdio_response.get("id"),
                http_response.get("id"),
                "Response IDs should match for {description}"
            );
        }
    }
}

// Test with actual HTTP transport implementation
#[tokio::test]
async fn test_actual_http_transport_parity() {
    unsafe {
        std::env::set_var("MCP_AUTH_REQUIRED", "false");
    }
    let transport = goldentooth_mcp::transport::HttpTransport::new(false);
    let addr = transport
        .start()
        .await
        .expect("Should start HTTP transport");

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let mut tester = TransportParityTester::new()
        .with_http_transport(addr)
        .await
        .expect("Should configure HTTP transport");

    // Test that stdio and HTTP transports give identical responses
    let ping_request = McpRequestBuilders::ping(1).build();
    let comparison = tester.compare_transports(ping_request).await;

    assert!(
        comparison.has_same_response_type(),
        "Both transports should succeed"
    );
    assert!(
        comparison.is_identical_success(),
        "Responses should be identical"
    );
}

#[tokio::test]
#[ignore] // Will be enabled once authentication is implemented
async fn test_authenticated_request_parity() {
    // Test that authenticated HTTP requests produce the same results as stdio
    // (stdio doesn't require auth, but the response content should be identical)

    // Test with valid authentication
    // Test that the actual MCP responses are identical regardless of transport
}

#[tokio::test]
#[ignore] // Will be enabled once SSE is implemented
async fn test_sse_response_content_parity() {
    // Test that SSE-delivered responses have identical content to stdio responses
    // Even though the delivery mechanism differs, the JSON-RPC content should be identical
}
