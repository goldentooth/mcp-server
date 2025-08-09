//! MCP protocol message processing logic
//!
//! This module contains the core message processing functions that can be
//! tested directly without subprocess overhead.

use crate::tools;
use crate::types::{McpError, McpMessage, McpRequest, McpResponse, McpStreams, MessageId};
use serde_json::Value;
use std::env;

/// Process a parsed MCP message and return appropriate response
pub async fn process_mcp_message(message: McpMessage, streams: &mut McpStreams) -> McpMessage {
    match message {
        McpMessage::Request(req) => process_mcp_request(req, streams).await,
        McpMessage::Response(_) => {
            // We shouldn't receive responses as a server
            streams
                .log_warn_safe("Received unexpected response message")
                .await;
            McpMessage::Error(McpError::invalid_request(
                MessageId::Number(0),
                Some(serde_json::json!({"reason": "Server should not receive response messages"})),
            ))
        }
        McpMessage::Error(_) => {
            // We shouldn't receive errors as a server
            streams
                .log_warn_safe("Received unexpected error message")
                .await;
            McpMessage::Error(McpError::invalid_request(
                MessageId::Number(0),
                Some(serde_json::json!({"reason": "Server should not receive error messages"})),
            ))
        }
    }
}

/// Process an MCP request and return appropriate response
pub async fn process_mcp_request(req: McpRequest, streams: &mut McpStreams) -> McpMessage {
    streams
        .log_debug_safe(&format!(
            "Processing {} request with ID {}",
            req.method, req.id
        ))
        .await;

    // Validate initialize requests since they need proper protocol setup
    if let crate::types::McpMethod::Initialize = req.method {
        if let Err(error_msg) = validate_initialize_params(&req.params) {
            streams
                .log_warn_safe(&format!("Initialize validation failed: {error_msg}"))
                .await;
            return McpMessage::Error(McpError::invalid_params(
                req.id.clone(),
                Some(serde_json::json!({"error": error_msg})),
            ));
        }
    }

    match req.method {
        crate::types::McpMethod::Initialize => {
            // Generate capabilities dynamically from type-safe tools
            let tool_names = vec![
                "cluster_ping",
                "cluster_status",
                "service_status",
                "shell_command",
                "resource_usage",
                "cluster_info",
                "journald_logs",
                "loki_logs",
                "screenshot_url",
                "screenshot_dashboard",
            ];

            McpMessage::Response(McpResponse::initialize_response(
                req.id.clone(),
                serde_json::json!({
                    "tools": tool_names
                }),
                serde_json::json!({
                    "name": env!("CARGO_PKG_NAME"),
                    "version": env!("CARGO_PKG_VERSION")
                }),
            ))
        }
        crate::types::McpMethod::Ping => {
            // Return pong response
            McpMessage::Response(McpResponse::pong(req.id.clone()))
        }
        crate::types::McpMethod::ToolsList => {
            // Generate tool list from type-safe tool definitions
            let tool_definitions = vec![
                serde_json::json!({
                    "name": "cluster_ping",
                    "description": "Ping all nodes in the Goldentooth cluster to check connectivity",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": false
                    }
                }),
                serde_json::json!({
                    "name": "cluster_status",
                    "description": "Get detailed status information for cluster nodes",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "node": {
                                "type": "string",
                                "description": "Specific node to check (optional)"
                            }
                        },
                        "additionalProperties": false
                    }
                }),
                serde_json::json!({
                    "name": "service_status",
                    "description": "Check the status of systemd services on cluster nodes",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "service": {
                                "type": "string",
                                "description": "Service name to check"
                            },
                            "node": {
                                "type": "string",
                                "description": "Specific node to check (optional)"
                            }
                        },
                        "required": ["service"],
                        "additionalProperties": false
                    }
                }),
                serde_json::json!({
                    "name": "shell_command",
                    "description": "Execute arbitrary shell commands on cluster nodes via SSH",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "Shell command to execute (security validated)"
                            },
                            "node": {
                                "type": "string",
                                "description": "Specific node to run on (optional)"
                            },
                            "as_root": {
                                "type": "boolean",
                                "description": "Whether to execute as root user"
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "Command timeout in seconds"
                            }
                        },
                        "required": ["command"],
                        "additionalProperties": false
                    }
                }), // Additional tools can be added here as they are implemented
            ];

            McpMessage::Response(McpResponse::tools_list_response(
                req.id.clone(),
                tool_definitions,
            ))
        }
        crate::types::McpMethod::ToolsCall => {
            // Extract tool name and arguments from params
            let params = req.params.unwrap_or_default();

            let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");

            let arguments = params
                .get("arguments")
                .unwrap_or(&serde_json::json!({}))
                .clone();

            if tool_name.is_empty() {
                return McpMessage::Error(McpError::invalid_params(
                    req.id.clone(),
                    Some(serde_json::json!({"error": "Missing required parameter 'name'"})),
                ));
            }

            // Parse arguments using type-safe system and execute the tool
            match tools::parse_tool_arguments(tool_name, arguments)
                .map(tools::execute_tool_type_safe)
            {
                Ok(future_result) => match future_result.await {
                    Ok(result) => McpMessage::Response(McpResponse::new(result, req.id.clone())),
                    Err(err) => McpMessage::Error(McpError::internal_error(
                        req.id.clone(),
                        Some(serde_json::json!({"error": err.error_info().message})),
                    )),
                },
                Err(parse_err) => McpMessage::Error(McpError::invalid_params(
                    req.id.clone(),
                    Some(serde_json::json!({"error": parse_err})),
                )),
            }
        }
        crate::types::McpMethod::ResourcesList => {
            // Return empty resources list for now
            McpMessage::Response(McpResponse::new(
                serde_json::json!({"resources": []}),
                req.id.clone(),
            ))
        }
        crate::types::McpMethod::ResourcesRead => McpMessage::Error(McpError::method_not_found(
            req.id.clone(),
            Some("Resources not yet implemented".to_string()),
        )),
        crate::types::McpMethod::PromptsList => {
            // Return empty prompts list for now
            McpMessage::Response(McpResponse::new(
                serde_json::json!({"prompts": []}),
                req.id.clone(),
            ))
        }
        crate::types::McpMethod::PromptsGet => McpMessage::Error(McpError::method_not_found(
            req.id.clone(),
            Some("Prompts not yet implemented".to_string()),
        )),
    }
}

/// Process a JSON string directly - useful for testing
pub async fn process_json_request(
    json_str: &str,
    streams: &mut McpStreams,
) -> Result<McpMessage, String> {
    match McpMessage::from_json_str(json_str) {
        Ok(message) => {
            streams
                .log_debug_safe(&format!("Parsed message with ID: {}", message.id()))
                .await;
            Ok(process_mcp_message(message, streams).await)
        }
        Err(e) => {
            streams
                .log_error_safe(&format!("Failed to parse JSON-RPC message: {e}"))
                .await;
            // Return error to caller so main loop can handle it appropriately
            // This allows implementation of circuit breaker logic and proper error handling
            Err(format!("JSON parse error: {e}"))
        }
    }
}

/// Validate initialize request parameters
///
/// The initialize method is special and requires protocol-level validation
fn validate_initialize_params(params: &Option<Value>) -> Result<(), String> {
    let params = params.as_ref().ok_or("initialize requires params")?;

    let obj = params.as_object().ok_or("params must be an object")?;

    // Validate protocolVersion
    let protocol_version = obj
        .get("protocolVersion")
        .ok_or("Missing required parameter: protocolVersion")?;

    let version_str = protocol_version
        .as_str()
        .ok_or("protocolVersion must be a string")?;

    // Validate supported protocol version
    if version_str != "2025-06-18" {
        return Err(format!(
            "Unsupported protocol version '{version_str}', expected '2025-06-18'"
        ));
    }

    // Validate capabilities is present and is an object
    let capabilities = obj
        .get("capabilities")
        .ok_or("Missing required parameter: capabilities")?;

    if !capabilities.is_object() {
        return Err("capabilities must be an object".to_string());
    }

    // Validate clientInfo is present and has required fields
    let client_info = obj
        .get("clientInfo")
        .ok_or("Missing required parameter: clientInfo")?;

    let client_obj = client_info
        .as_object()
        .ok_or("clientInfo must be an object")?;

    // Client name is required
    let _name = client_obj
        .get("name")
        .ok_or("Missing required parameter: clientInfo.name")?;

    // Version is required
    let _version = client_obj
        .get("version")
        .ok_or("Missing required parameter: clientInfo.version")?;

    Ok(())
}
