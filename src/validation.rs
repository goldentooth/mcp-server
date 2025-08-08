//! Input validation for MCP requests
//!
//! Provides comprehensive validation beyond basic JSON-RPC parsing,
//! including parameter validation, schema enforcement, and security checks.

use crate::types::{McpError, McpMethod, McpRequest, MessageId};
use serde_json::Value;

/// Validation errors that can occur during request processing
#[derive(Debug, Clone)]
pub enum ValidationError {
    MissingRequiredParam(String),
    InvalidParamType(String, String),  // param name, expected type
    InvalidParamValue(String, String), // param name, reason
    SchemaViolation(String),
    SecurityViolation(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::MissingRequiredParam(param) => {
                write!(f, "Missing required parameter: {param}")
            }
            ValidationError::InvalidParamType(param, expected) => {
                write!(
                    f,
                    "Invalid type for parameter '{param}': expected {expected}"
                )
            }
            ValidationError::InvalidParamValue(param, reason) => {
                write!(f, "Invalid value for parameter '{param}': {reason}")
            }
            ValidationError::SchemaViolation(details) => {
                write!(f, "Schema violation: {details}")
            }
            ValidationError::SecurityViolation(details) => {
                write!(f, "Security violation: {details}")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// Validate an MCP request comprehensively
pub fn validate_mcp_request(request: &McpRequest) -> Result<(), ValidationError> {
    match &request.method {
        McpMethod::Initialize => validate_initialize_params(&request.params, &request.id),
        McpMethod::Ping => validate_ping_params(&request.params),
        McpMethod::ToolsList => validate_tools_list_params(&request.params),
        McpMethod::ToolsCall => validate_tools_call_params(&request.params),
        McpMethod::ResourcesList => validate_resources_list_params(&request.params),
        McpMethod::ResourcesRead => validate_resources_read_params(&request.params),
        McpMethod::PromptsList => validate_prompts_list_params(&request.params),
        McpMethod::PromptsGet => validate_prompts_get_params(&request.params),
    }
}

/// Validate initialize request parameters
fn validate_initialize_params(
    params: &Option<Value>,
    _id: &MessageId,
) -> Result<(), ValidationError> {
    let params = params.as_ref().ok_or_else(|| {
        ValidationError::MissingRequiredParam("initialize requires params".to_string())
    })?;

    let obj = params.as_object().ok_or_else(|| {
        ValidationError::InvalidParamType("params".to_string(), "object".to_string())
    })?;

    // Validate protocolVersion
    let protocol_version = obj
        .get("protocolVersion")
        .ok_or_else(|| ValidationError::MissingRequiredParam("protocolVersion".to_string()))?;

    let version_str = protocol_version.as_str().ok_or_else(|| {
        ValidationError::InvalidParamType("protocolVersion".to_string(), "string".to_string())
    })?;

    // Validate supported protocol version
    if version_str != "2024-11-05" {
        return Err(ValidationError::InvalidParamValue(
            "protocolVersion".to_string(),
            format!("unsupported version '{version_str}', expected '2024-11-05'"),
        ));
    }

    // Validate capabilities is present and is an object
    let capabilities = obj
        .get("capabilities")
        .ok_or_else(|| ValidationError::MissingRequiredParam("capabilities".to_string()))?;

    if !capabilities.is_object() {
        return Err(ValidationError::InvalidParamType(
            "capabilities".to_string(),
            "object".to_string(),
        ));
    }

    // Validate clientInfo is present and has required fields
    let client_info = obj
        .get("clientInfo")
        .ok_or_else(|| ValidationError::MissingRequiredParam("clientInfo".to_string()))?;

    let client_obj = client_info.as_object().ok_or_else(|| {
        ValidationError::InvalidParamType("clientInfo".to_string(), "object".to_string())
    })?;

    // Client name is required
    let _name = client_obj
        .get("name")
        .ok_or_else(|| ValidationError::MissingRequiredParam("clientInfo.name".to_string()))?;

    // Version is required
    let _version = client_obj
        .get("version")
        .ok_or_else(|| ValidationError::MissingRequiredParam("clientInfo.version".to_string()))?;

    Ok(())
}

/// Validate ping request parameters (should have no params)
fn validate_ping_params(params: &Option<Value>) -> Result<(), ValidationError> {
    // Ping should not have parameters, but if it does, ignore them
    // This is lenient to be compatible with different MCP implementations
    let _ = params;
    Ok(())
}

/// Validate tools/list parameters
fn validate_tools_list_params(params: &Option<Value>) -> Result<(), ValidationError> {
    if let Some(params) = params {
        // If params are provided, they should be an empty object or can be ignored
        if let Some(obj) = params.as_object() {
            if !obj.is_empty() {
                // For now, be lenient and allow parameters to tools/list
                // This maintains compatibility with different MCP implementations
            }
        }
    }
    Ok(())
}

/// Validate tools/call parameters
fn validate_tools_call_params(params: &Option<Value>) -> Result<(), ValidationError> {
    let params = params.as_ref().ok_or_else(|| {
        ValidationError::MissingRequiredParam("tools/call requires params".to_string())
    })?;

    let obj = params.as_object().ok_or_else(|| {
        ValidationError::InvalidParamType("params".to_string(), "object".to_string())
    })?;

    // Tool name is required
    let name = obj
        .get("name")
        .ok_or_else(|| ValidationError::MissingRequiredParam("name".to_string()))?;

    let name_str = name.as_str().ok_or_else(|| {
        ValidationError::InvalidParamType("name".to_string(), "string".to_string())
    })?;

    // Validate tool name is one of our supported tools
    let valid_tools = &[
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

    if !valid_tools.contains(&name_str) {
        return Err(ValidationError::InvalidParamValue(
            "name".to_string(),
            format!("unsupported tool '{name_str}'"),
        ));
    }

    // Arguments should be present and be an object
    let _arguments = obj
        .get("arguments")
        .ok_or_else(|| ValidationError::MissingRequiredParam("arguments".to_string()))?;

    // Tool-specific argument validation
    validate_tool_arguments(name_str, &obj.get("arguments"))?;

    Ok(())
}

/// Validate arguments for specific tools
fn validate_tool_arguments(
    tool_name: &str,
    arguments: &Option<&Value>,
) -> Result<(), ValidationError> {
    let args =
        arguments.ok_or_else(|| ValidationError::MissingRequiredParam("arguments".to_string()))?;

    let args_obj = args.as_object().ok_or_else(|| {
        ValidationError::InvalidParamType("arguments".to_string(), "object".to_string())
    })?;

    match tool_name {
        "cluster_ping" => {
            // No arguments required for cluster_ping
            Ok(())
        }
        "cluster_status" => {
            // Optional node parameter
            if let Some(node) = args_obj.get("node") {
                let _node_str = node.as_str().ok_or_else(|| {
                    ValidationError::InvalidParamType("node".to_string(), "string".to_string())
                })?;
            }
            Ok(())
        }
        "service_status" => {
            // Required service parameter
            let _service = args_obj
                .get("service")
                .ok_or_else(|| ValidationError::MissingRequiredParam("service".to_string()))?
                .as_str()
                .ok_or_else(|| {
                    ValidationError::InvalidParamType("service".to_string(), "string".to_string())
                })?;

            // Optional node parameter
            if let Some(node) = args_obj.get("node") {
                let _node_str = node.as_str().ok_or_else(|| {
                    ValidationError::InvalidParamType("node".to_string(), "string".to_string())
                })?;
            }
            Ok(())
        }
        "shell_command" => {
            // Required command parameter
            let command = args_obj
                .get("command")
                .ok_or_else(|| ValidationError::MissingRequiredParam("command".to_string()))?
                .as_str()
                .ok_or_else(|| {
                    ValidationError::InvalidParamType("command".to_string(), "string".to_string())
                })?;

            // Security validation: prevent dangerous commands
            if command.trim().is_empty() {
                return Err(ValidationError::InvalidParamValue(
                    "command".to_string(),
                    "command cannot be empty".to_string(),
                ));
            }

            // Basic security checks
            let dangerous_patterns = &["rm -rf", ">/dev/", "mkfs", "dd if=", ":(){ :|:& };:"];
            for pattern in dangerous_patterns {
                if command.contains(pattern) {
                    return Err(ValidationError::SecurityViolation(format!(
                        "potentially dangerous command pattern detected: {pattern}"
                    )));
                }
            }

            Ok(())
        }
        "screenshot_url" => {
            // Required url parameter
            let url = args_obj
                .get("url")
                .ok_or_else(|| ValidationError::MissingRequiredParam("url".to_string()))?
                .as_str()
                .ok_or_else(|| {
                    ValidationError::InvalidParamType("url".to_string(), "string".to_string())
                })?;

            // Basic URL validation
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err(ValidationError::InvalidParamValue(
                    "url".to_string(),
                    "URL must start with http:// or https://".to_string(),
                ));
            }

            Ok(())
        }
        _ => {
            // For other tools, basic validation that arguments is an object
            Ok(())
        }
    }
}

/// Validate other method parameters (stubs for now)
fn validate_resources_list_params(_params: &Option<Value>) -> Result<(), ValidationError> {
    Ok(())
}

fn validate_resources_read_params(_params: &Option<Value>) -> Result<(), ValidationError> {
    Ok(())
}

fn validate_prompts_list_params(_params: &Option<Value>) -> Result<(), ValidationError> {
    Ok(())
}

fn validate_prompts_get_params(_params: &Option<Value>) -> Result<(), ValidationError> {
    Ok(())
}

/// Convert ValidationError to McpError response
pub fn validation_error_to_mcp_error(validation_error: ValidationError, id: MessageId) -> McpError {
    match validation_error {
        ValidationError::MissingRequiredParam(_)
        | ValidationError::InvalidParamType(_, _)
        | ValidationError::InvalidParamValue(_, _)
        | ValidationError::SchemaViolation(_) => McpError::invalid_params(
            id,
            Some(serde_json::json!({"error": validation_error.to_string()})),
        ),
        ValidationError::SecurityViolation(_) => {
            // Return more generic error for security violations to not leak implementation details
            McpError::invalid_request(
                id,
                Some(serde_json::json!({"error": "Request rejected due to security policy"})),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    #[test]
    fn test_validate_initialize_success() {
        let params = serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        });

        let request = McpRequest::new(McpMethod::Initialize, Some(params), MessageId::Number(1));

        assert!(validate_mcp_request(&request).is_ok());
    }

    #[test]
    fn test_validate_initialize_missing_params() {
        let request = McpRequest::new(McpMethod::Initialize, None, MessageId::Number(1));

        let result = validate_mcp_request(&request);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("initialize requires params")
        );
    }

    #[test]
    fn test_validate_shell_command_security() {
        let params = serde_json::json!({
            "name": "shell_command",
            "arguments": {
                "command": "rm -rf /"
            }
        });

        let request = McpRequest::new(McpMethod::ToolsCall, Some(params), MessageId::Number(1));

        let result = validate_mcp_request(&request);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Security violation") || error_msg.contains("dangerous"));
    }
}
