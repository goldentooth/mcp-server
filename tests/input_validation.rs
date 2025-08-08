use goldentooth_mcp::protocol::process_json_request;
use goldentooth_mcp::types::McpStreams;
use serde_json::json;

#[tokio::test]
async fn test_initialize_request_validation() {
    let mut streams = McpStreams::new();

    // Test missing protocolVersion
    let invalid_init = json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "id": 1,
        "params": {
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"}
        }
    })
    .to_string();

    let result = process_json_request(&invalid_init, &mut streams).await;
    assert!(result.is_ok());
    if let Ok(response) = result {
        let json_str = response.to_json_string().unwrap();
        // Should be an error response due to missing protocolVersion
        assert!(
            json_str.contains("error"),
            "Missing protocolVersion should cause error"
        );
    }

    // Test unsupported protocolVersion
    let invalid_version = json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "id": 2,
        "params": {
            "protocolVersion": "1.0.0",  // Wrong version
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"}
        }
    })
    .to_string();

    let result = process_json_request(&invalid_version, &mut streams).await;
    assert!(result.is_ok());
    if let Ok(response) = result {
        let json_str = response.to_json_string().unwrap();
        assert!(
            json_str.contains("error"),
            "Wrong protocolVersion should cause error"
        );
    }

    // Test valid initialize request
    let valid_init = json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "id": 3,
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"}
        }
    })
    .to_string();

    let result = process_json_request(&valid_init, &mut streams).await;
    assert!(result.is_ok());
    if let Ok(response) = result {
        let json_str = response.to_json_string().unwrap();
        // Should be a successful response, not an error
        assert!(
            json_str.contains("result"),
            "Valid initialize should return result"
        );
        assert!(
            !json_str.contains("error"),
            "Valid initialize should not return error"
        );
    }
}

#[tokio::test]
async fn test_tools_call_validation() {
    let mut streams = McpStreams::new();

    // Test unsupported tool name
    let invalid_tool = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 1,
        "params": {
            "name": "nonexistent_tool",
            "arguments": {}
        }
    })
    .to_string();

    let result = process_json_request(&invalid_tool, &mut streams).await;
    assert!(result.is_ok());
    if let Ok(response) = result {
        let json_str = response.to_json_string().unwrap();
        assert!(
            json_str.contains("error"),
            "Unsupported tool should cause error"
        );
    }

    // Test valid tool call
    let valid_tool = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 2,
        "params": {
            "name": "cluster_ping",
            "arguments": {}
        }
    })
    .to_string();

    let result = process_json_request(&valid_tool, &mut streams).await;
    assert!(result.is_ok());
    if let Ok(response) = result {
        let json_str = response.to_json_string().unwrap();
        // For now, tools return "not implemented" error, but structure should be valid
        assert!(json_str.contains("error") && json_str.contains("not yet implemented"));
    }
}

#[tokio::test]
async fn test_security_validation() {
    let mut streams = McpStreams::new();

    // Test potentially dangerous shell command (this test will fail until we implement validation)
    let dangerous_command = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 1,
        "params": {
            "name": "shell_command",
            "arguments": {
                "command": "rm -rf /"
            }
        }
    })
    .to_string();

    let result = process_json_request(&dangerous_command, &mut streams).await;
    assert!(result.is_ok());
    if let Ok(response) = result {
        let json_str = response.to_json_string().unwrap();
        // Should reject dangerous commands due to security policy
        // This will initially fail until we implement security validation
        assert!(
            json_str.contains("error"),
            "Dangerous commands should be rejected"
        );
    }
}

#[tokio::test]
async fn test_parameter_type_validation() {
    let mut streams = McpStreams::new();

    // Test service_status with missing required parameter
    let missing_service = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 1,
        "params": {
            "name": "service_status",
            "arguments": {
                "node": "allyrion"  // Missing required "service" parameter
            }
        }
    })
    .to_string();

    let result = process_json_request(&missing_service, &mut streams).await;
    assert!(result.is_ok());
    if let Ok(response) = result {
        let json_str = response.to_json_string().unwrap();
        assert!(
            json_str.contains("error"),
            "Missing required parameter should cause error"
        );
    }

    // Test URL validation
    let invalid_url = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 2,
        "params": {
            "name": "screenshot_url",
            "arguments": {
                "url": "not-a-url"  // Invalid URL format
            }
        }
    })
    .to_string();

    let result = process_json_request(&invalid_url, &mut streams).await;
    assert!(result.is_ok());
    if let Ok(response) = result {
        let json_str = response.to_json_string().unwrap();
        assert!(json_str.contains("error"), "Invalid URL should cause error");
    }
}

#[tokio::test]
async fn test_empty_parameters_validation() {
    let mut streams = McpStreams::new();

    // Test tools/list with parameters (should be empty)
    let tools_list_with_params = json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "id": 1,
        "params": {
            "unexpected": "parameter"
        }
    })
    .to_string();

    let result = process_json_request(&tools_list_with_params, &mut streams).await;
    assert!(result.is_ok());
    if let Ok(response) = result {
        let json_str = response.to_json_string().unwrap();
        // This should either succeed (ignoring params) or fail with validation error
        // The current implementation might be lenient, so we check it doesn't crash
        assert!(!json_str.is_empty(), "Should return some response");
    }
}
