//! Comprehensive validation tests to improve coverage
//!
//! These tests target all validation paths and edge cases in validation.rs

use goldentooth_mcp::types::{McpMethod, McpRequest, MessageId};
use goldentooth_mcp::validation::validate_mcp_request;
use serde_json::json;

#[test]
fn test_initialize_validation_comprehensive() {
    // Test missing params
    let request = McpRequest::new(McpMethod::Initialize, None, MessageId::Number(1));
    let result = validate_mcp_request(&request);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("initialize requires params")
    );

    // Test non-object params
    let request = McpRequest::new(
        McpMethod::Initialize,
        Some(json!("string params")),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("object"));

    // Test non-string protocolVersion
    let request = McpRequest::new(
        McpMethod::Initialize,
        Some(json!({
            "protocolVersion": 123,
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"}
        })),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("protocolVersion"));

    // Test wrong protocol version
    let request = McpRequest::new(
        McpMethod::Initialize,
        Some(json!({
            "protocolVersion": "1.0.0",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"}
        })),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("unsupported version")
    );

    // Test missing capabilities
    let request = McpRequest::new(
        McpMethod::Initialize,
        Some(json!({
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "test", "version": "1.0"}
        })),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("capabilities"));

    // Test non-object capabilities
    let request = McpRequest::new(
        McpMethod::Initialize,
        Some(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": "string",
            "clientInfo": {"name": "test", "version": "1.0"}
        })),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("capabilities"));

    // Test missing clientInfo
    let request = McpRequest::new(
        McpMethod::Initialize,
        Some(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {}
        })),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("clientInfo"));

    // Test non-object clientInfo
    let request = McpRequest::new(
        McpMethod::Initialize,
        Some(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": "string"
        })),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("clientInfo"));

    // Test missing clientInfo.name
    let request = McpRequest::new(
        McpMethod::Initialize,
        Some(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"version": "1.0"}
        })),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("clientInfo.name"));

    // Test missing clientInfo.version
    let request = McpRequest::new(
        McpMethod::Initialize,
        Some(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test"}
        })),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("clientInfo.version")
    );
}

#[test]
fn test_ping_validation() {
    // Ping should accept no params
    let request = McpRequest::new(McpMethod::Ping, None, MessageId::Number(1));
    let result = validate_mcp_request(&request);
    assert!(result.is_ok());

    // Ping should accept any params (lenient)
    let request = McpRequest::new(
        McpMethod::Ping,
        Some(json!({"extra": "params"})),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_ok());
}

#[test]
fn test_tools_list_validation() {
    // Tools list should accept no params
    let request = McpRequest::new(McpMethod::ToolsList, None, MessageId::Number(1));
    let result = validate_mcp_request(&request);
    assert!(result.is_ok());

    // Tools list should be lenient with params
    let request = McpRequest::new(
        McpMethod::ToolsList,
        Some(json!({"cursor": "test"})),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_ok());

    // Even with non-object params
    let request = McpRequest::new(
        McpMethod::ToolsList,
        Some(json!("string params")),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_ok());
}

#[test]
fn test_tools_call_validation_comprehensive() {
    // Test missing params
    let request = McpRequest::new(McpMethod::ToolsCall, None, MessageId::Number(1));
    let result = validate_mcp_request(&request);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("tools/call requires params")
    );

    // Test non-object params
    let request = McpRequest::new(
        McpMethod::ToolsCall,
        Some(json!("string params")),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("object"));

    // Test missing name
    let request = McpRequest::new(
        McpMethod::ToolsCall,
        Some(json!({"arguments": {}})),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("name"));

    // Test non-string name
    let request = McpRequest::new(
        McpMethod::ToolsCall,
        Some(json!({"name": 123, "arguments": {}})),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("name"));

    // Test missing arguments
    let request = McpRequest::new(
        McpMethod::ToolsCall,
        Some(json!({"name": "cluster_ping"})),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("arguments"));
}

#[test]
fn test_tool_specific_validation() {
    // Test cluster_status with node parameter
    let request = McpRequest::new(
        McpMethod::ToolsCall,
        Some(json!({
            "name": "cluster_status",
            "arguments": {"node": "allyrion"}
        })),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_ok());

    // Test cluster_status with invalid node type
    let request = McpRequest::new(
        McpMethod::ToolsCall,
        Some(json!({
            "name": "cluster_status",
            "arguments": {"node": 123}
        })),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("node"));

    // Test service_status with missing service
    let request = McpRequest::new(
        McpMethod::ToolsCall,
        Some(json!({
            "name": "service_status",
            "arguments": {"node": "allyrion"}
        })),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("service"));

    // Test service_status with non-string service
    let request = McpRequest::new(
        McpMethod::ToolsCall,
        Some(json!({
            "name": "service_status",
            "arguments": {"service": 123}
        })),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("service"));

    // Test service_status with invalid node type
    let request = McpRequest::new(
        McpMethod::ToolsCall,
        Some(json!({
            "name": "service_status",
            "arguments": {"service": "consul", "node": 456}
        })),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("node"));

    // Test shell_command security validation
    let request = McpRequest::new(
        McpMethod::ToolsCall,
        Some(json!({
            "name": "shell_command",
            "arguments": {"command": "rm -rf /tmp"}
        })),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("dangerous"));

    // Test shell_command with empty command
    let request = McpRequest::new(
        McpMethod::ToolsCall,
        Some(json!({
            "name": "shell_command",
            "arguments": {"command": ""}
        })),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("empty"));

    // Test shell_command with whitespace only
    let request = McpRequest::new(
        McpMethod::ToolsCall,
        Some(json!({
            "name": "shell_command",
            "arguments": {"command": "   \t  "}
        })),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("empty"));

    // Test all dangerous patterns
    let dangerous_patterns = [
        "rm -rf /",
        ">/dev/null",
        "mkfs.ext4",
        "dd if=/dev/zero",
        ":(){ :|:& };:",
    ];

    for pattern in &dangerous_patterns {
        let request = McpRequest::new(
            McpMethod::ToolsCall,
            Some(json!({
                "name": "shell_command",
                "arguments": {"command": format!("echo {} test", pattern)}
            })),
            MessageId::Number(1),
        );
        let result = validate_mcp_request(&request);
        assert!(
            result.is_err(),
            "Should reject dangerous pattern: {pattern}"
        );
        assert!(result.unwrap_err().to_string().contains("dangerous"));
    }

    // Test screenshot_url validation
    let request = McpRequest::new(
        McpMethod::ToolsCall,
        Some(json!({
            "name": "screenshot_url",
            "arguments": {"url": "not-a-url"}
        })),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("http"));

    // Test screenshot_url with valid URLs
    for url in &["http://example.com", "https://example.com"] {
        let request = McpRequest::new(
            McpMethod::ToolsCall,
            Some(json!({
                "name": "screenshot_url",
                "arguments": {"url": url}
            })),
            MessageId::Number(1),
        );
        let result = validate_mcp_request(&request);
        assert!(result.is_ok(), "Should accept valid URL: {url}");
    }

    // Test tools with non-object arguments
    let request = McpRequest::new(
        McpMethod::ToolsCall,
        Some(json!({
            "name": "cluster_ping",
            "arguments": "not an object"
        })),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("arguments"));

    // Test unknown tools
    let request = McpRequest::new(
        McpMethod::ToolsCall,
        Some(json!({
            "name": "unknown_tool",
            "arguments": {}
        })),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("unsupported tool"));

    // Test all valid tools
    let valid_tools = [
        "cluster_ping",
        "cluster_status",
        "service_status",
        "resource_usage",
        "cluster_info",
        "shell_command",
        "journald_logs",
        "loki_logs",
        "screenshot_url",
        "screenshot_dashboard",
    ];

    for tool in &valid_tools {
        let mut args = json!({});

        // Add required arguments for specific tools
        match *tool {
            "service_status" => {
                args = json!({"service": "consul"});
            }
            "shell_command" => {
                args = json!({"command": "echo safe"});
            }
            "screenshot_url" => {
                args = json!({"url": "https://example.com"});
            }
            _ => {}
        }

        let request = McpRequest::new(
            McpMethod::ToolsCall,
            Some(json!({
                "name": tool,
                "arguments": args
            })),
            MessageId::Number(1),
        );
        let result = validate_mcp_request(&request);
        assert!(result.is_ok(), "Should accept valid tool: {tool}");
    }
}

#[test]
fn test_other_methods_validation() {
    // Test resources methods (currently stubs that accept anything)
    let request = McpRequest::new(McpMethod::ResourcesList, None, MessageId::Number(1));
    let result = validate_mcp_request(&request);
    assert!(result.is_ok());

    let request = McpRequest::new(
        McpMethod::ResourcesList,
        Some(json!({"any": "params"})),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_ok());

    let request = McpRequest::new(McpMethod::ResourcesRead, None, MessageId::Number(1));
    let result = validate_mcp_request(&request);
    assert!(result.is_ok());

    let request = McpRequest::new(
        McpMethod::ResourcesRead,
        Some(json!({"uri": "test://resource"})),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_ok());

    // Test prompts methods (currently stubs that accept anything)
    let request = McpRequest::new(McpMethod::PromptsList, None, MessageId::Number(1));
    let result = validate_mcp_request(&request);
    assert!(result.is_ok());

    let request = McpRequest::new(
        McpMethod::PromptsList,
        Some(json!({"any": "params"})),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_ok());

    let request = McpRequest::new(McpMethod::PromptsGet, None, MessageId::Number(1));
    let result = validate_mcp_request(&request);
    assert!(result.is_ok());

    let request = McpRequest::new(
        McpMethod::PromptsGet,
        Some(json!({"name": "test_prompt"})),
        MessageId::Number(1),
    );
    let result = validate_mcp_request(&request);
    assert!(result.is_ok());
}

#[test]
fn test_validation_error_conversion() {
    use goldentooth_mcp::validation::{ValidationError, validation_error_to_mcp_error};

    // Test different error types conversion to MCP errors
    let errors = [
        ValidationError::MissingRequiredParam("test".to_string()),
        ValidationError::InvalidParamType("param".to_string(), "string".to_string()),
        ValidationError::InvalidParamValue("param".to_string(), "reason".to_string()),
        ValidationError::SchemaViolation("details".to_string()),
        ValidationError::SecurityViolation("dangerous command".to_string()),
    ];

    for error in &errors {
        let mcp_error = validation_error_to_mcp_error(error.clone(), MessageId::Number(1));
        let json_str = mcp_error.to_json_string().unwrap();

        // All should produce valid JSON-RPC errors
        assert!(json_str.contains("error"));
        assert!(json_str.contains("\"id\":1"));

        // Security violations should be more generic
        if matches!(error, ValidationError::SecurityViolation(_)) {
            assert!(json_str.contains("security policy"));
        } else {
            // Other errors should include the original error message
            assert!(json_str.contains(&error.to_string()));
        }
    }
}

#[test]
fn test_validation_error_display() {
    use goldentooth_mcp::validation::ValidationError;

    // Test all error display formatting
    let error = ValidationError::MissingRequiredParam("test".to_string());
    assert!(
        error
            .to_string()
            .contains("Missing required parameter: test")
    );

    let error = ValidationError::InvalidParamType("param".to_string(), "string".to_string());
    assert!(
        error
            .to_string()
            .contains("Invalid type for parameter 'param': expected string")
    );

    let error = ValidationError::InvalidParamValue("param".to_string(), "reason".to_string());
    assert!(
        error
            .to_string()
            .contains("Invalid value for parameter 'param': reason")
    );

    let error = ValidationError::SchemaViolation("details".to_string());
    assert!(error.to_string().contains("Schema violation: details"));

    let error = ValidationError::SecurityViolation("details".to_string());
    assert!(error.to_string().contains("Security violation: details"));
}
