//! SSE Stream Management Tests
//!
//! Tests for Server-Sent Events streaming functionality including stream lifecycle,
//! cleanup behavior, concurrent connections, and compliance with requirements.

use goldentooth_mcp::transport::HttpTransport;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::{sleep, timeout};

mod common;
use common::test_helpers::{McpRequestBuilders, ResponseAssertions};

/// SSE Stream test helper for managing event stream connections
pub struct SseStreamTester {
    client: Client<hyper_util::client::legacy::connect::HttpConnector, Full<hyper::body::Bytes>>,
    base_url: String,
    auth_token: Option<String>,
    _received_events: Vec<String>,
}

impl SseStreamTester {
    /// Create a new SSE stream tester
    pub async fn new(server_addr: SocketAddr) -> Result<Self, Box<dyn std::error::Error>> {
        let client = Client::builder(TokioExecutor::new()).build_http();
        let base_url = format!("http://{server_addr}");

        Ok(Self {
            client,
            base_url,
            auth_token: None,
            _received_events: Vec::new(),
        })
    }

    /// Set authentication token for SSE requests
    pub fn with_auth_token(mut self, token: String) -> Self {
        self.auth_token = Some(token);
        self
    }

    /// Get the SSE endpoint URL
    pub fn sse_endpoint_url(&self) -> String {
        format!("{}/mcp", self.base_url)
    }

    /// Establish an SSE connection to the server
    pub async fn connect_sse(
        &self,
    ) -> Result<hyper::Response<hyper::body::Incoming>, Box<dyn std::error::Error>> {
        let mut req_builder = Request::builder()
            .method(Method::GET)
            .uri(self.sse_endpoint_url())
            .header("Accept", "text/event-stream")
            .header("Cache-Control", "no-cache")
            .header("Connection", "keep-alive");

        if let Some(ref token) = self.auth_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {token}"));
        }

        let request = req_builder.body(Full::new(hyper::body::Bytes::new()))?;
        Ok(self.client.request(request).await?)
    }

    /// Send a JSON-RPC message over POST and expect SSE response
    pub async fn send_jsonrpc_expect_sse(
        &self,
        request: Value,
    ) -> Result<hyper::Response<hyper::body::Incoming>, Box<dyn std::error::Error>> {
        let json_body = request.to_string();
        let mut req_builder = Request::builder()
            .method(Method::POST)
            .uri(self.sse_endpoint_url())
            .header("Content-Type", "application/json")
            .header("Accept", "text/event-stream")
            .header("Content-Length", json_body.len());

        if let Some(ref token) = self.auth_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {token}"));
        }

        let request = req_builder.body(Full::new(hyper::body::Bytes::from(json_body)))?;
        Ok(self.client.request(request).await?)
    }

    /// Parse SSE events from response body
    pub async fn parse_sse_events(
        response: hyper::Response<hyper::body::Incoming>,
    ) -> Result<Vec<SseEvent>, Box<dyn std::error::Error>> {
        let body_bytes = response.into_body().collect().await?.to_bytes();
        let body_str = String::from_utf8(body_bytes.to_vec())?;

        let events = Self::parse_sse_stream(&body_str);
        Ok(events)
    }

    /// Parse SSE stream format
    fn parse_sse_stream(data: &str) -> Vec<SseEvent> {
        let mut events = Vec::new();
        let mut current_event = SseEvent::new();

        for line in data.lines() {
            if line.is_empty() {
                // Empty line indicates end of event
                if current_event.has_data() {
                    events.push(current_event);
                    current_event = SseEvent::new();
                }
            } else if let Some(stripped) = line.strip_prefix("data: ") {
                current_event.add_data(stripped);
            } else if let Some(stripped) = line.strip_prefix("event: ") {
                current_event.event_type = Some(stripped.to_string());
            } else if let Some(stripped) = line.strip_prefix("id: ") {
                current_event.id = Some(stripped.to_string());
            } else if let Some(stripped) = line.strip_prefix("retry: ") {
                if let Ok(retry_ms) = stripped.parse() {
                    current_event.retry = Some(retry_ms);
                }
            }
        }

        // Add final event if it has data
        if current_event.has_data() {
            events.push(current_event);
        }

        events
    }

    /// Check if server closes connection properly
    pub async fn verify_connection_closed(
        &self,
        mut response: hyper::Response<hyper::body::Incoming>,
    ) -> bool {
        // Try to read from the stream with timeout
        match timeout(Duration::from_millis(100), response.body_mut().frame()).await {
            Ok(Some(Ok(_))) => false, // Still receiving data
            Ok(Some(Err(_))) => true, // Error indicates closed connection
            Ok(None) => true,         // End of stream
            Err(_) => true,           // Timeout indicates no more data
        }
    }
}

/// Represents a Server-Sent Event
#[derive(Debug, Clone, PartialEq)]
pub struct SseEvent {
    pub event_type: Option<String>,
    pub id: Option<String>,
    pub data: String,
    pub retry: Option<u64>,
}

impl SseEvent {
    fn new() -> Self {
        Self {
            event_type: None,
            id: None,
            data: String::new(),
            retry: None,
        }
    }

    fn add_data(&mut self, data: &str) {
        if !self.data.is_empty() {
            self.data.push('\n');
        }
        self.data.push_str(data);
    }

    fn has_data(&self) -> bool {
        !self.data.is_empty()
    }

    /// Parse JSON data if possible
    pub fn parse_json_data(&self) -> Result<Value, serde_json::Error> {
        serde_json::from_str(&self.data)
    }
}

/// Mock SSE server for testing stream behavior
pub struct MockSseServer {
    addr: SocketAddr,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl MockSseServer {
    /// Start a mock SSE server
    pub async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        // Spawn server task
        tokio::spawn(async move {
            let mut shutdown_rx = shutdown_rx;
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept_result = listener.accept() => {
                        if let Ok((stream, _)) = accept_result {
                            tokio::spawn(Self::handle_connection(stream));
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

    async fn handle_connection(stream: tokio::net::TcpStream) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = stream;
        let mut buffer = [0; 1024];

        // Read request
        if let Ok(n) = stream.read(&mut buffer).await {
            let request = String::from_utf8_lossy(&buffer[..n]);

            if request.contains("GET /mcp") && request.contains("text/event-stream") {
                // Send SSE response
                let response = "HTTP/1.1 200 OK\r\n\
                               Content-Type: text/event-stream\r\n\
                               Cache-Control: no-cache\r\n\
                               Connection: keep-alive\r\n\
                               Access-Control-Allow-Origin: *\r\n\
                               \r\n\
                               data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\r\n\
                               \r\n";

                let _ = stream.write_all(response.as_bytes()).await;

                // Close connection after sending response (testing requirement)
                let _ = stream.shutdown().await;
            } else if request.contains("POST /mcp") {
                // Send SSE response to POST request
                let response = "HTTP/1.1 200 OK\r\n\
                               Content-Type: text/event-stream\r\n\
                               Cache-Control: no-cache\r\n\
                               Connection: close\r\n\
                               Access-Control-Allow-Origin: *\r\n\
                               \r\n\
                               data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\r\n\
                               \r\n";

                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        }
    }
}

impl Drop for MockSseServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

// SSE Stream Lifecycle Tests

#[tokio::test]
async fn test_sse_event_parsing() {
    let sse_data = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
    let events = SseStreamTester::parse_sse_stream(sse_data);

    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.data, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");

    let json_data = event.parse_json_data().expect("Should parse JSON");
    ResponseAssertions::assert_success_response(&json_data, 1);
}

#[tokio::test]
async fn test_sse_multiline_data_parsing() {
    let sse_data = "data: line1\ndata: line2\ndata: line3\n\n";
    let events = SseStreamTester::parse_sse_stream(sse_data);

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].data, "line1\nline2\nline3");
}

#[tokio::test]
async fn test_sse_event_with_metadata() {
    let sse_data = "event: message\nid: 123\nretry: 1000\ndata: test data\n\n";
    let events = SseStreamTester::parse_sse_stream(sse_data);

    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.event_type, Some("message".to_string()));
    assert_eq!(event.id, Some("123".to_string()));
    assert_eq!(event.retry, Some(1000));
    assert_eq!(event.data, "test data");
}

#[tokio::test]
async fn test_sse_multiple_events() {
    let sse_data = "data: event1\n\ndata: event2\n\ndata: event3\n\n";
    let events = SseStreamTester::parse_sse_stream(sse_data);

    assert_eq!(events.len(), 3);
    assert_eq!(events[0].data, "event1");
    assert_eq!(events[1].data, "event2");
    assert_eq!(events[2].data, "event3");
}

#[tokio::test]
async fn test_mock_sse_server_lifecycle() {
    let server = MockSseServer::start()
        .await
        .expect("Should start mock server");
    let addr = server.addr();

    // Verify server is listening
    let tester = SseStreamTester::new(addr)
        .await
        .expect("Should create tester");

    // Connection should be possible
    let connect_result = timeout(Duration::from_millis(100), tester.connect_sse()).await;
    assert!(
        connect_result.is_ok(),
        "Should be able to connect to mock server"
    );

    drop(server);

    // Give time for cleanup
    sleep(Duration::from_millis(10)).await;
}

#[tokio::test]
async fn test_sse_stream_closes_after_response() {
    let server = MockSseServer::start()
        .await
        .expect("Should start mock server");
    let addr = server.addr();
    let tester = SseStreamTester::new(addr)
        .await
        .expect("Should create tester");

    // Send JSON-RPC request expecting SSE response
    let ping_request = McpRequestBuilders::ping(1).build();
    let response = tester
        .send_jsonrpc_expect_sse(ping_request)
        .await
        .expect("Should send request successfully");

    // Verify response is SSE format
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/event-stream"
    );

    // Parse SSE events from response
    let events = SseStreamTester::parse_sse_events(response)
        .await
        .expect("Should parse SSE events");

    // Should receive exactly one event
    assert_eq!(events.len(), 1);

    // Event should contain valid JSON-RPC response
    let json_response = events[0].parse_json_data().expect("Should parse JSON");
    ResponseAssertions::assert_success_response(&json_response, 1);
}

#[tokio::test]
async fn test_sse_connection_headers() {
    let server = MockSseServer::start()
        .await
        .expect("Should start mock server");
    let addr = server.addr();
    let tester = SseStreamTester::new(addr)
        .await
        .expect("Should create tester");

    let response = tester.connect_sse().await.expect("Should connect");

    // Verify SSE-specific headers
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/event-stream"
    );
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-cache");

    // Connection should be managed appropriately
    let connection_header = response.headers().get("connection");
    assert!(
        connection_header == Some(&"keep-alive".parse().unwrap())
            || connection_header == Some(&"close".parse().unwrap()),
        "Connection header should be either keep-alive or close"
    );
}

#[tokio::test]
async fn test_sse_stream_format_compliance() {
    // Test that our SSE format complies with HTML5 spec
    let json_response = json!({
        "jsonrpc": "2.0",
        "id": 42,
        "result": {"status": "ok"}
    });

    // Format as SSE event
    let sse_formatted = format!("data: {json_response}\n\n");

    // Parse it back
    let events = SseStreamTester::parse_sse_stream(&sse_formatted);
    assert_eq!(events.len(), 1);

    let parsed_json = events[0].parse_json_data().expect("Should parse JSON");
    assert_eq!(parsed_json, json_response);
}

// Stream Cleanup Tests

#[tokio::test]
async fn test_stream_cleanup_on_error() {
    // Test that streams are properly cleaned up when errors occur
    let invalid_addr: SocketAddr = "127.0.0.1:1".parse().unwrap(); // Likely unused port
    let tester = SseStreamTester::new(invalid_addr)
        .await
        .expect("Should create tester");

    // Connection should fail quickly
    let connect_result = timeout(Duration::from_millis(100), tester.connect_sse()).await;
    assert!(connect_result.is_err() || connect_result.unwrap().is_err());
}

#[tokio::test]
async fn test_concurrent_sse_connections_basic() {
    let server = MockSseServer::start()
        .await
        .expect("Should start mock server");
    let addr = server.addr();

    // Create multiple testers (simulating concurrent clients)
    let tester1 = SseStreamTester::new(addr)
        .await
        .expect("Should create tester1");
    let tester2 = SseStreamTester::new(addr)
        .await
        .expect("Should create tester2");

    // Both should be able to connect simultaneously
    let (result1, result2) = tokio::join!(tester1.connect_sse(), tester2.connect_sse());

    assert!(result1.is_ok(), "First connection should succeed");
    assert!(result2.is_ok(), "Second connection should succeed");
}

// Test actual HTTP server SSE integration
#[tokio::test]
async fn test_actual_http_server_sse_integration() {
    unsafe {
        std::env::set_var("MCP_AUTH_REQUIRED", "false");
    }
    let transport = goldentooth_mcp::transport::HttpTransport::new(false);
    let addr = transport
        .start()
        .await
        .expect("Should start HTTP transport");

    sleep(Duration::from_millis(50)).await;

    let tester = SseStreamTester::new(addr)
        .await
        .expect("Should create tester");

    // Test SSE response from actual server
    let ping_request = McpRequestBuilders::ping(1).build();
    let response = tester
        .send_jsonrpc_expect_sse(ping_request)
        .await
        .expect("Should send SSE request");

    // Verify SSE response format
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/event-stream"
    );

    // Parse SSE events
    let events = SseStreamTester::parse_sse_events(response)
        .await
        .expect("Should parse SSE events");

    assert_eq!(events.len(), 1);
    let json_response = events[0].parse_json_data().expect("Should parse JSON");
    ResponseAssertions::assert_success_response(&json_response, 1);
}

#[tokio::test]
async fn test_sse_authentication_required() {
    // Test that SSE connections require proper authentication
    let transport = HttpTransport::new(true); // auth_required = true
    let addr = transport
        .start()
        .await
        .expect("Failed to start HTTP transport");

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{addr}/mcp"))
        .header("Accept", "text/event-stream")
        .send()
        .await
        .expect("Failed to send SSE request");

    // Should require authentication for SSE connections
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn test_sse_origin_header_validation() {
    // Test Origin header validation for SSE connections
    unsafe {
        std::env::set_var("MCP_AUTH_REQUIRED", "false");
    }
    let transport = HttpTransport::new(false);
    let addr = transport
        .start()
        .await
        .expect("Failed to start HTTP transport");

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{addr}/mcp"))
        .header("Accept", "text/event-stream")
        .header("Origin", "http://malicious.com")
        .send()
        .await
        .expect("Failed to send SSE request");

    // Should validate Origin header for SSE connections
    assert_eq!(response.status(), 403);
}
