use goldentooth_mcp::protocol::process_json_request;
use goldentooth_mcp::types::McpStreams;
use serde_json::{Value, json};

#[tokio::test]
async fn test_tools_call_cluster_ping_success() {
    // Test tools/call with cluster_ping tool
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 1,
        "params": {
            "name": "cluster_ping",
            "arguments": {}
        }
    });

    let response = process_mcp_request_direct(request).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 1);

    // Should have a result field with ping results
    assert!(response["result"].is_object());

    // Should contain results for cluster nodes
    let result = &response["result"];
    assert!(result["nodes"].is_object());

    // Verify we have some node results (even if some fail)
    let nodes = result["nodes"].as_object().unwrap();
    assert!(
        !nodes.is_empty(),
        "Should have results for at least one node"
    );
}

#[tokio::test]
async fn test_tools_call_invalid_tool() {
    // Test tools/call with non-existent tool
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 2,
        "params": {
            "name": "nonexistent_tool",
            "arguments": {}
        }
    });

    let response = process_mcp_request_direct(request).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 2);

    // Should have an error field
    assert!(response["error"].is_object());

    // Should be an invalid params error (caught by validation layer)
    assert_eq!(response["error"]["code"], -32602);

    // Should indicate unsupported tool
    let error_data = &response["error"]["data"];
    assert!(
        error_data["error"]
            .as_str()
            .unwrap()
            .contains("unsupported tool")
    );
}

#[tokio::test]
async fn test_tools_call_missing_name_parameter() {
    // Test tools/call without required 'name' parameter
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 3,
        "params": {
            "arguments": {}
        }
    });

    let response = process_mcp_request_direct(request).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 3);

    // Should have an error field
    assert!(response["error"].is_object());

    // Should be an invalid params error
    assert_eq!(response["error"]["code"], -32602);

    // Should indicate missing name parameter
    let error_data = &response["error"]["data"];
    assert!(
        error_data["error"]
            .as_str()
            .unwrap()
            .contains("Missing required parameter")
    );
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
