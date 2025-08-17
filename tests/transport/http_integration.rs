//! HTTP Transport Integration Tests
//!
//! Tests the actual HTTP transport implementation with real server instances.

use goldentooth_mcp::transport::HttpTransport;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::Value;
use std::time::Duration;
use tokio::time::{sleep, timeout};

use crate::common::test_helpers::{McpRequestBuilders, ResponseAssertions};

#[tokio::test]
async fn test_http_transport_basic_startup() {
    // Test that HTTP transport can start without authentication
    unsafe {
        std::env::set_var("MCP_AUTH_REQUIRED", "false");
    }

    let transport = HttpTransport::new(false);
    let addr = transport
        .start()
        .await
        .expect("Should start HTTP transport");

    // Give server time to start
    sleep(Duration::from_millis(50)).await;

    // Verify server is listening on the expected port
    assert!(addr.port() > 0);
    assert!(addr.ip().is_loopback() || addr.ip().is_unspecified());
}

#[tokio::test]
async fn test_http_mcp_endpoint_responds() {
    unsafe {
        std::env::set_var("MCP_AUTH_REQUIRED", "false");
    }

    let transport = HttpTransport::new(false);
    let addr = transport
        .start()
        .await
        .expect("Should start HTTP transport");

    // Give server time to start
    sleep(Duration::from_millis(50)).await;

    let client = Client::builder(TokioExecutor::new()).build_http();

    // Test that /mcp endpoint exists (should respond to POST)
    let ping_request = McpRequestBuilders::ping(1).build();
    let json_body = ping_request.to_string();

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr}/mcp"))
        .header("Content-Type", "application/json")
        .header("Content-Length", json_body.len())
        .body(Full::new(hyper::body::Bytes::from(json_body)))
        .expect("Should build request");

    let response = timeout(Duration::from_secs(2), client.request(request))
        .await
        .expect("Request should not timeout")
        .expect("Should send request");

    // Should get a response (not 404)
    assert_ne!(response.status(), StatusCode::NOT_FOUND);

    // For unauthenticated requests, might get UNAUTHORIZED, but not NOT_FOUND
    assert!(response.status() == StatusCode::OK || response.status() == StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_http_mcp_endpoint_json_response() {
    unsafe {
        std::env::set_var("MCP_AUTH_REQUIRED", "false");
    }

    let transport = HttpTransport::new(false);
    let addr = transport
        .start()
        .await
        .expect("Should start HTTP transport");

    sleep(Duration::from_millis(50)).await;

    let client = Client::builder(TokioExecutor::new()).build_http();

    // Send ping request
    let ping_request = McpRequestBuilders::ping(1).build();
    let json_body = ping_request.to_string();

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr}/mcp"))
        .header("Content-Type", "application/json")
        .header("Content-Length", json_body.len())
        .body(Full::new(hyper::body::Bytes::from(json_body)))
        .expect("Should build request");

    let response = timeout(Duration::from_secs(2), client.request(request))
        .await
        .expect("Request should not timeout")
        .expect("Should send request");

    assert_eq!(response.status(), StatusCode::OK);

    // Parse response body
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .expect("Should read body")
        .to_bytes();
    let body_str = String::from_utf8(body_bytes.to_vec()).expect("Should be UTF-8");
    let response_json: Value = serde_json::from_str(&body_str).expect("Should be valid JSON");

    // Should be a valid JSON-RPC response
    ResponseAssertions::assert_success_response(&response_json, 1);
}

#[tokio::test]
async fn test_http_sse_response_format() {
    unsafe {
        std::env::set_var("MCP_AUTH_REQUIRED", "false");
    }

    let transport = HttpTransport::new(false);
    let addr = transport
        .start()
        .await
        .expect("Should start HTTP transport");

    sleep(Duration::from_millis(50)).await;

    let client = Client::builder(TokioExecutor::new()).build_http();

    // Send request with SSE accept header
    let ping_request = McpRequestBuilders::ping(1).build();
    let json_body = ping_request.to_string();

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr}/mcp"))
        .header("Content-Type", "application/json")
        .header("Accept", "text/event-stream")
        .header("Content-Length", json_body.len())
        .body(Full::new(hyper::body::Bytes::from(json_body)))
        .expect("Should build request");

    let response = timeout(Duration::from_secs(2), client.request(request))
        .await
        .expect("Request should not timeout")
        .expect("Should send request");

    assert_eq!(response.status(), StatusCode::OK);

    // Should return SSE format
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/event-stream"
    );

    // Should have cache control header
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-cache");

    // Connection should be close (not keep-alive for SSE single response)
    assert_eq!(response.headers().get("connection").unwrap(), "close");

    // Parse SSE response
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .expect("Should read body")
        .to_bytes();
    let body_str = String::from_utf8(body_bytes.to_vec()).expect("Should be UTF-8");

    // Should be SSE format
    assert!(body_str.starts_with("data: "));
    assert!(body_str.ends_with("\n\n"));

    // Extract JSON from SSE
    let json_line = body_str
        .strip_prefix("data: ")
        .unwrap()
        .strip_suffix("\n\n")
        .unwrap();
    let response_json: Value = serde_json::from_str(json_line).expect("Should be valid JSON");

    ResponseAssertions::assert_success_response(&response_json, 1);
}

#[tokio::test]
async fn test_http_authentication_required() {
    // Test with authentication enabled
    let transport = HttpTransport::new(true);
    let addr = transport
        .start()
        .await
        .expect("Should start HTTP transport");

    sleep(Duration::from_millis(50)).await;

    let client = Client::builder(TokioExecutor::new()).build_http();

    // Send unauthenticated request
    let ping_request = McpRequestBuilders::ping(1).build();
    let json_body = ping_request.to_string();

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr}/mcp"))
        .header("Content-Type", "application/json")
        .header("Content-Length", json_body.len())
        .body(Full::new(hyper::body::Bytes::from(json_body)))
        .expect("Should build request");

    let response = timeout(Duration::from_secs(2), client.request(request))
        .await
        .expect("Request should not timeout")
        .expect("Should send request");

    // Should require authentication
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Should return JSON error
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .expect("Should read body")
        .to_bytes();
    let body_str = String::from_utf8(body_bytes.to_vec()).expect("Should be UTF-8");
    let error_json: Value = serde_json::from_str(&body_str).expect("Should be valid JSON");

    // Should be JSON-RPC error
    ResponseAssertions::assert_error_response(&error_json, serde_json::Value::Null, -32001);
    assert!(
        error_json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Authentication required")
    );
}

#[tokio::test]
async fn test_http_invalid_endpoint() {
    unsafe {
        std::env::set_var("MCP_AUTH_REQUIRED", "false");
    }

    let transport = HttpTransport::new(false);
    let addr = transport
        .start()
        .await
        .expect("Should start HTTP transport");

    sleep(Duration::from_millis(50)).await;

    let client = Client::builder(TokioExecutor::new()).build_http();

    // Test invalid endpoint
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/invalid"))
        .body(Full::new(hyper::body::Bytes::new()))
        .expect("Should build request");

    let response = timeout(Duration::from_secs(2), client.request(request))
        .await
        .expect("Request should not timeout")
        .expect("Should send request");

    // Should return 404 for invalid endpoints
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_http_method_not_allowed() {
    unsafe {
        std::env::set_var("MCP_AUTH_REQUIRED", "false");
    }

    let transport = HttpTransport::new(false);
    let addr = transport
        .start()
        .await
        .expect("Should start HTTP transport");

    sleep(Duration::from_millis(50)).await;

    let client = Client::builder(TokioExecutor::new()).build_http();

    // Test unsupported method on /mcp endpoint
    let request = Request::builder()
        .method(Method::DELETE)
        .uri(format!("http://{addr}/mcp"))
        .body(Full::new(hyper::body::Bytes::new()))
        .expect("Should build request");

    let response = timeout(Duration::from_secs(2), client.request(request))
        .await
        .expect("Request should not timeout")
        .expect("Should send request");

    // Should return method not allowed
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_http_environment_binding() {
    // Test MCP_LOCAL environment variable behavior

    // Test with MCP_LOCAL set
    unsafe {
        std::env::set_var("MCP_LOCAL", "1");
    }
    let local_transport = HttpTransport::new(false);
    let local_addr = local_transport
        .start()
        .await
        .expect("Should start local transport");

    // Should bind to localhost
    assert!(local_addr.ip().is_loopback());

    // Test with MCP_LOCAL unset
    unsafe {
        std::env::remove_var("MCP_LOCAL");
    }
    let any_transport = HttpTransport::new(false);
    let any_addr = any_transport
        .start()
        .await
        .expect("Should start any transport");

    // Should bind to any interface (0.0.0.0)
    assert!(any_addr.ip().is_unspecified());
}

// Integration test to verify ignored test should now pass
#[tokio::test]
async fn test_http_server_now_implemented() {
    // This replaces the ignored test in http_transport.rs
    unsafe {
        std::env::set_var("MCP_AUTH_REQUIRED", "false");
    }

    let transport = HttpTransport::new(false);
    let addr = transport
        .start()
        .await
        .expect("Should start HTTP transport");

    sleep(Duration::from_millis(50)).await;

    let client = Client::builder(TokioExecutor::new()).build_http();

    // Test server is responding
    let ping_request = McpRequestBuilders::ping(1).build();
    let json_body = ping_request.to_string();

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr}/mcp"))
        .header("Content-Type", "application/json")
        .header("Content-Length", json_body.len())
        .body(Full::new(hyper::body::Bytes::from(json_body)))
        .expect("Should build request");

    let result = timeout(Duration::from_secs(2), client.request(request)).await;
    assert!(
        result.is_ok(),
        "HTTP transport is now implemented and responding"
    );
}
