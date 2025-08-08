//! MCP protocol message processing logic
//!
//! This module contains the core message processing functions that can be
//! tested directly without subprocess overhead.

use crate::tools;
use crate::types::{McpError, McpMessage, McpRequest, McpResponse, McpStreams, MessageId};
use crate::validation::{validate_mcp_request, validation_error_to_mcp_error};
use std::env;

/// Process a parsed MCP message and return appropriate response
pub async fn process_mcp_message(message: McpMessage, streams: &mut McpStreams) -> McpMessage {
    match message {
        McpMessage::Request(req) => process_mcp_request(req, streams).await,
        McpMessage::Response(_) => {
            // We shouldn't receive responses as a server
            if let Err(e) = streams
                .log_warn("Received unexpected response message")
                .await
            {
                eprintln!("Failed to log warning: {e}");
            }
            McpMessage::Error(McpError::invalid_request(
                MessageId::Number(0),
                Some(serde_json::json!({"reason": "Server should not receive response messages"})),
            ))
        }
        McpMessage::Error(_) => {
            // We shouldn't receive errors as a server
            if let Err(e) = streams.log_warn("Received unexpected error message").await {
                eprintln!("Failed to log warning: {e}");
            }
            McpMessage::Error(McpError::invalid_request(
                MessageId::Number(0),
                Some(serde_json::json!({"reason": "Server should not receive error messages"})),
            ))
        }
    }
}

/// Process an MCP request and return appropriate response
pub async fn process_mcp_request(req: McpRequest, streams: &mut McpStreams) -> McpMessage {
    if let Err(e) = streams
        .log_debug(&format!(
            "Processing {} request with ID {}",
            req.method, req.id
        ))
        .await
    {
        eprintln!("Failed to log debug: {e}");
    }

    // Validate the request thoroughly before processing
    if let Err(validation_error) = validate_mcp_request(&req) {
        if let Err(e) = streams
            .log_warn(&format!(
                "Request validation failed for {}: {}",
                req.method, validation_error
            ))
            .await
        {
            eprintln!("Failed to log validation warning: {e}");
        }
        return McpMessage::Error(validation_error_to_mcp_error(
            validation_error,
            req.id.clone(),
        ));
    }

    match req.method {
        crate::types::McpMethod::Initialize => {
            // Return basic initialization response
            McpMessage::Response(McpResponse::initialize_response(
                req.id.clone(),
                serde_json::json!({
                    "tools": ["cluster_ping", "cluster_status", "service_status", "resource_usage", "cluster_info"]
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
            // Return list of available tools
            let tools = vec![
                serde_json::json!({
                    "name": "cluster_ping",
                    "description": "Ping all nodes in the goldentooth cluster to check their status",
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
                                "description": "Specific node to check (e.g., 'allyrion', 'jast'). If not provided, checks all nodes."
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
                                "description": "Service name to check (e.g., 'consul', 'nomad', 'vault')"
                            },
                            "node": {
                                "type": "string",
                                "description": "Specific node to check. If not provided, checks all nodes."
                            }
                        },
                        "required": ["service"],
                        "additionalProperties": false
                    }
                }),
                serde_json::json!({
                    "name": "resource_usage",
                    "description": "Get memory and disk usage information for cluster nodes",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "node": {
                                "type": "string",
                                "description": "Specific node to check. If not provided, checks all nodes."
                            }
                        },
                        "additionalProperties": false
                    }
                }),
                serde_json::json!({
                    "name": "cluster_info",
                    "description": "Get comprehensive cluster information including node status and service membership",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": false
                    }
                }),
            ];
            McpMessage::Response(McpResponse::tools_list_response(req.id.clone(), tools))
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

            // Execute the tool
            match tools::execute_tool(tool_name, arguments).await {
                Ok(result) => McpMessage::Response(McpResponse::new(result, req.id.clone())),
                Err(err) => McpMessage::Error(McpError::internal_error(
                    req.id.clone(),
                    Some(serde_json::json!({"error": err})),
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
            if let Err(e) = streams
                .log_debug(&format!("Parsed message with ID: {}", message.id()))
                .await
            {
                eprintln!("Failed to log debug: {e}");
            }
            Ok(process_mcp_message(message, streams).await)
        }
        Err(e) => {
            if let Err(log_err) = streams
                .log_error(&format!("Failed to parse JSON-RPC message: {e}"))
                .await
            {
                eprintln!("Failed to log error: {log_err}");
            }
            // Return error to caller so main loop can handle it appropriately
            // This allows implementation of circuit breaker logic and proper error handling
            Err(format!("JSON parse error: {e}"))
        }
    }
}
