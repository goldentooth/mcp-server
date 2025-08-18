use base64::prelude::*;
use goldentooth_mcp::protocol::process_json_request;
use goldentooth_mcp::types::McpStreams;
use serde_json::{Value, json};

#[tokio::test]
async fn test_initialize_handshake() {
    let request = json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "id": 1,
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        }
    });

    let response = process_mcp_request_direct(request).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 1);
    assert!(response["result"]["capabilities"].is_object());
    assert!(response["result"]["serverInfo"].is_object());
}

#[tokio::test]
async fn test_ping_pong() {
    // Basic ping/notifications.ping roundtrip
    let request = json!({
        "jsonrpc": "2.0",
        "method": "ping",
        "id": 2
    });

    let response = process_mcp_request_direct(request).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 2);
    assert!(response["result"].is_object());
}

#[tokio::test]
async fn test_tools_list() {
    // tools/list request returns list of available tools
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "id": 3,
        "params": {}
    });

    let response = process_mcp_request_direct(request).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 3);
    assert!(response["result"]["tools"].is_array());

    let tools = response["result"]["tools"].as_array().unwrap();
    assert!(!tools.is_empty()); // We should have some tools

    // Verify tools have the required structure
    for tool in tools {
        assert!(tool["name"].is_string());
        assert!(tool["description"].is_string());
        assert!(tool["inputSchema"].is_object());
    }
}

/// Helper function to process an MCP request directly (fast, no subprocess)
async fn process_mcp_request_direct(request: Value) -> Value {
    use std::io::Cursor;

    // Create test streams that capture output to memory buffers
    let stdout_buf = Vec::new();
    let stderr_buf = Vec::new();

    let mut streams =
        McpStreams::new_with_writers(Cursor::new(stdout_buf), Cursor::new(stderr_buf));

    // Process the request directly using our protocol module
    let request_str = request.to_string();
    let response = process_json_request(&request_str, &mut streams)
        .await
        .expect("Failed to process JSON request");

    // Convert the response to JSON value for easy assertions
    let response_json = response
        .to_json_string()
        .expect("Failed to serialize response");
    serde_json::from_str(&response_json).expect("Failed to parse response JSON")
}

#[tokio::test]
async fn test_screenshot_url_basic() {
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 20,
        "params": {
            "name": "screenshot_url",
            "arguments": {
                "url": "https://example.com"
            }
        }
    });

    let response = process_mcp_request_direct(request).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 20);
    assert!(response["result"].is_object());

    let result = &response["result"];
    assert_eq!(result["url"], "https://example.com");
    assert_eq!(result["width"], 1920);
    assert_eq!(result["height"], 1080);
    assert_eq!(result["screenshot_format"], "png");
    assert!(result["screenshot_base64"].is_string());
    assert!(result["duration_seconds"].is_number());
    assert!(result["captured_at"].is_string());
    assert!(result["note"].as_str().unwrap().contains("Placeholder"));
}

#[tokio::test]
async fn test_screenshot_url_with_custom_dimensions() {
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 21,
        "params": {
            "name": "screenshot_url",
            "arguments": {
                "url": "https://example.com",
                "width": 800,
                "height": 600,
                "wait_timeout_ms": 10000
            }
        }
    });

    let response = process_mcp_request_direct(request).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 21);
    assert!(response["result"].is_object());

    let result = &response["result"];
    assert_eq!(result["url"], "https://example.com");
    assert_eq!(result["width"], 800);
    assert_eq!(result["height"], 600);
    assert_eq!(result["wait_timeout_ms"], 10000);
}

#[tokio::test]
async fn test_screenshot_dashboard_basic() {
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 22,
        "params": {
            "name": "screenshot_dashboard",
            "arguments": {
                "dashboard_url": "https://grafana.services.goldentooth.net/dashboard"
            }
        }
    });

    let response = process_mcp_request_direct(request).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 22);
    assert!(response["result"].is_object());

    let result = &response["result"];
    assert_eq!(
        result["dashboard_url"],
        "https://grafana.services.goldentooth.net/dashboard"
    );
    assert_eq!(result["screenshot_format"], "png");
    assert_eq!(result["authentication"], "bypass_planned");
    assert!(result["screenshot_base64"].is_string());
    assert!(result["duration_seconds"].is_number());
    assert!(result["captured_at"].is_string());
    assert_eq!(result["viewport"]["width"], 1920);
    assert_eq!(result["viewport"]["height"], 1080);
    assert!(result["note"].as_str().unwrap().contains("Placeholder"));
}

#[tokio::test]
async fn test_screenshot_url_invalid_url() {
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 23,
        "params": {
            "name": "screenshot_url",
            "arguments": {
                "url": "not-a-valid-url"
            }
        }
    });

    let response = process_mcp_request_direct(request).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 23);

    // Should have an error field due to invalid URL
    assert!(response["error"].is_object());
    assert_eq!(response["error"]["code"], -32602); // Invalid params
}

#[tokio::test]
async fn test_screenshot_dashboard_missing_url() {
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 24,
        "params": {
            "name": "screenshot_dashboard",
            "arguments": {}
        }
    });

    let response = process_mcp_request_direct(request).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 24);

    // Should have an error field due to missing dashboard_url parameter
    assert!(response["error"].is_object());
    assert_eq!(response["error"]["code"], -32602); // Invalid params
}

#[tokio::test]
async fn test_screenshot_base64_format_validation() {
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 25,
        "params": {
            "name": "screenshot_url",
            "arguments": {
                "url": "https://example.com"
            }
        }
    });

    let response = process_mcp_request_direct(request).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 25);
    assert!(response["result"].is_object());

    let result = &response["result"];
    let base64_data = result["screenshot_base64"].as_str().unwrap();

    // Validate base64 decoding works
    let decoded = base64::prelude::BASE64_STANDARD.decode(base64_data);
    assert!(decoded.is_ok(), "Base64 screenshot data should be valid");

    let image_bytes = decoded.unwrap();
    assert!(!image_bytes.is_empty(), "Decoded image should not be empty");

    // Check PNG header (89 50 4E 47)
    assert_eq!(image_bytes[0], 0x89, "PNG signature byte 1");
    assert_eq!(image_bytes[1], 0x50, "PNG signature byte 2");
    assert_eq!(image_bytes[2], 0x4E, "PNG signature byte 3");
    assert_eq!(image_bytes[3], 0x47, "PNG signature byte 4");
}

#[tokio::test]
async fn test_utf8_encoding() {
    // Test that UTF-8 characters are handled properly in MCP messages
    let request = json!({
        "jsonrpc": "2.0",
        "method": "ping",
        "id": "unicode-test-🌍",
        "params": {
            "text": "Hello 世界 🌍 émojis and ñoñó"
        }
    });

    let response = process_mcp_request_direct(request).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], "unicode-test-🌍");
    assert!(response["result"].is_object());
}
