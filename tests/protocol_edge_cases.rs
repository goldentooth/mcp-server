//! Edge case tests for protocol.rs to improve coverage
//!
//! These tests target the uncovered paths in protocol processing

use goldentooth_mcp::protocol::{process_json_request, process_mcp_message, process_mcp_request};
use goldentooth_mcp::types::{
    McpError, McpMessage, McpMethod, McpRequest, McpResponse, McpStreams, MessageId,
};
use serde_json::json;

#[tokio::test]
async fn test_process_mcp_message_with_unexpected_response() {
    let mut streams = McpStreams::new();

    // Create a response message (server should not receive these)
    let response = McpMessage::Response(McpResponse::pong(MessageId::Number(1)));

    let result = process_mcp_message(response, &mut streams).await;

    // Should return error message indicating server shouldn't receive responses
    if let McpMessage::Error(error) = result {
        let json_str = error.to_json_string().unwrap();
        assert!(json_str.contains("Server should not receive response messages"));
    } else {
        panic!("Expected error message for unexpected response");
    }
}

#[tokio::test]
async fn test_process_mcp_message_with_unexpected_error() {
    let mut streams = McpStreams::new();

    // Create an error message (server should not receive these)
    let error = McpMessage::Error(McpError::invalid_request(
        MessageId::Number(1),
        Some(json!({"test": "error"})),
    ));

    let result = process_mcp_message(error, &mut streams).await;

    // Should return error message indicating server shouldn't receive error messages
    if let McpMessage::Error(error) = result {
        let json_str = error.to_json_string().unwrap();
        assert!(json_str.contains("Server should not receive error messages"));
    } else {
        panic!("Expected error message for unexpected error");
    }
}

#[tokio::test]
async fn test_all_mcp_methods_coverage() {
    let mut streams = McpStreams::new();

    // Test initialize
    let init_request = McpRequest::new(
        McpMethod::Initialize,
        Some(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"}
        })),
        MessageId::Number(1),
    );

    let result = process_mcp_request(init_request, &mut streams).await;
    if let McpMessage::Response(response) = result {
        let json_str = response.to_json_string().unwrap();
        assert!(json_str.contains("tools"));
    } else {
        panic!("Initialize should return success response");
    }

    // Test ping
    let ping_request = McpRequest::new(
        McpMethod::Ping,
        None,
        MessageId::String("ping-test".to_string()),
    );

    let result = process_mcp_request(ping_request, &mut streams).await;
    if let McpMessage::Response(_) = result {
        // Success
    } else {
        panic!("Ping should return success response");
    }

    // Test tools/list
    let tools_request = McpRequest::new(McpMethod::ToolsList, None, MessageId::Number(3));

    let result = process_mcp_request(tools_request, &mut streams).await;
    if let McpMessage::Response(response) = result {
        let json_str = response.to_json_string().unwrap();
        assert!(json_str.contains("cluster_ping"));
    } else {
        panic!("Tools list should return success response");
    }

    // Test resources/list (should return empty list)
    let resources_request = McpRequest::new(McpMethod::ResourcesList, None, MessageId::Number(4));

    let result = process_mcp_request(resources_request, &mut streams).await;
    if let McpMessage::Response(response) = result {
        let json_str = response.to_json_string().unwrap();
        assert!(json_str.contains("resources"));
    } else {
        panic!("Resources list should return success response");
    }

    // Test resources/read (should return error)
    let resources_read_request = McpRequest::new(
        McpMethod::ResourcesRead,
        Some(json!({"uri": "test://resource"})),
        MessageId::Number(5),
    );

    let result = process_mcp_request(resources_read_request, &mut streams).await;
    if let McpMessage::Error(error) = result {
        let json_str = error.to_json_string().unwrap();
        assert!(json_str.contains("method_not_found") || json_str.contains("not yet implemented"));
    } else {
        panic!("Resources read should return error (not implemented)");
    }

    // Test prompts/list (should return empty list)
    let prompts_request = McpRequest::new(McpMethod::PromptsList, None, MessageId::Number(6));

    let result = process_mcp_request(prompts_request, &mut streams).await;
    if let McpMessage::Response(response) = result {
        let json_str = response.to_json_string().unwrap();
        assert!(json_str.contains("prompts"));
    } else {
        panic!("Prompts list should return success response");
    }

    // Test prompts/get (should return error)
    let prompts_get_request = McpRequest::new(
        McpMethod::PromptsGet,
        Some(json!({"name": "test_prompt"})),
        MessageId::Number(7),
    );

    let result = process_mcp_request(prompts_get_request, &mut streams).await;
    if let McpMessage::Error(error) = result {
        let json_str = error.to_json_string().unwrap();
        assert!(json_str.contains("method_not_found") || json_str.contains("not yet implemented"));
    } else {
        panic!("Prompts get should return error (not implemented)");
    }

    // Test tools/call (should return error for now)
    let tools_call_request = McpRequest::new(
        McpMethod::ToolsCall,
        Some(json!({
            "name": "cluster_ping",
            "arguments": {}
        })),
        MessageId::Number(8),
    );

    let result = process_mcp_request(tools_call_request, &mut streams).await;
    if let McpMessage::Error(error) = result {
        let json_str = error.to_json_string().unwrap();
        assert!(json_str.contains("not yet implemented"));
    } else {
        panic!("Tools call should return error (not implemented)");
    }
}

#[tokio::test]
async fn test_json_parsing_edge_cases() {
    let mut streams = McpStreams::new();

    // Test various malformed JSON
    let test_cases = [
        // Completely invalid
        ("not json", "should fail"),
        // Valid JSON but not MCP message
        (r#"{"valid": "json", "but": "not mcp"}"#, "should fail"),
        // Missing required fields
        (r#"{"jsonrpc": "2.0"}"#, "should fail"),
        // Wrong JSON-RPC version
        (
            r#"{"jsonrpc": "1.0", "method": "test", "id": 1}"#,
            "should fail",
        ),
        // Null values
        (
            r#"{"jsonrpc": "2.0", "method": null, "id": 1}"#,
            "should fail",
        ),
        // Invalid ID type
        (
            r#"{"jsonrpc": "2.0", "method": "ping", "id": {"object": "not allowed"}}"#,
            "should fail",
        ),
    ];

    for (json_str, description) in &test_cases {
        let result = process_json_request(json_str, &mut streams).await;
        assert!(result.is_err(), "Case '{json_str}' {description}");
    }
}

#[tokio::test]
async fn test_validation_error_handling() {
    let mut streams = McpStreams::new();

    // Test request that will fail validation
    let invalid_init = json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "id": 1,
        "params": {
            // Missing required protocolVersion
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"}
        }
    })
    .to_string();

    let result = process_json_request(&invalid_init, &mut streams).await;
    assert!(result.is_ok(), "Should return error response, not Err");

    if let Ok(McpMessage::Error(error)) = result {
        let json_str = error.to_json_string().unwrap();
        assert!(json_str.contains("protocolVersion"));
    } else {
        panic!("Expected validation error response");
    }
}

#[tokio::test]
async fn test_message_id_variations() {
    let mut streams = McpStreams::new();

    // Test different ID types
    let test_cases = [
        // String ID
        (
            json!({
                "jsonrpc": "2.0",
                "method": "ping",
                "id": "string-id"
            }),
            "string ID should work",
        ),
        // Number ID
        (
            json!({
                "jsonrpc": "2.0",
                "method": "ping",
                "id": 42
            }),
            "number ID should work",
        ),
        // Zero ID
        (
            json!({
                "jsonrpc": "2.0",
                "method": "ping",
                "id": 0
            }),
            "zero ID should work",
        ),
        // Large ID
        (
            json!({
                "jsonrpc": "2.0",
                "method": "ping",
                "id": 999999999
            }),
            "large ID should work",
        ),
    ];

    for (message, description) in &test_cases {
        let json_str = message.to_string();
        let result = process_json_request(&json_str, &mut streams).await;
        assert!(result.is_ok(), "Case: {description}");

        if let Ok(response) = result {
            let response_json = response.to_json_string().unwrap();
            // Response should include the original ID
            let original_id = message.get("id").unwrap();
            if original_id.is_string() {
                assert!(response_json.contains(original_id.as_str().unwrap()));
            } else {
                assert!(response_json.contains(&original_id.to_string()));
            }
        }
    }
}

#[tokio::test]
async fn test_logging_during_processing() {
    let mut streams = McpStreams::new();

    // Test request that logs debug information
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "id": "log-test"
    })
    .to_string();

    let result = process_json_request(&request, &mut streams).await;
    assert!(result.is_ok());

    // The function should have logged the message ID and processing info
    // We can't easily capture stderr in tests, but we can verify no errors occurred
}
