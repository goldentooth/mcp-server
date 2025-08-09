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
            "protocolVersion": "2024-11-05",
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
