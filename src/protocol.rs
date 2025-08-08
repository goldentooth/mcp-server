//! MCP protocol message processing logic
//!
//! This module contains the core message processing functions that can be
//! tested directly without subprocess overhead.

use crate::types::{McpError, McpMessage, McpRequest, McpResponse, McpStreams, MessageId};
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
                eprintln!("Failed to log warning: {}", e);
            }
            McpMessage::Error(McpError::invalid_request(
                MessageId::Number(0),
                Some(serde_json::json!({"reason": "Server should not receive response messages"})),
            ))
        }
        McpMessage::Error(_) => {
            // We shouldn't receive errors as a server
            if let Err(e) = streams.log_warn("Received unexpected error message").await {
                eprintln!("Failed to log warning: {}", e);
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
        eprintln!("Failed to log debug: {}", e);
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
            // For now, return method not found for actual tool calls
            // TODO: Implement actual tool execution
            McpMessage::Error(McpError::method_not_found(
                req.id.clone(),
                Some("Tool execution not yet implemented".to_string()),
            ))
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
                eprintln!("Failed to log debug: {}", e);
            }
            Ok(process_mcp_message(message, streams).await)
        }
        Err(e) => {
            if let Err(log_err) = streams
                .log_error(&format!("Failed to parse JSON-RPC message: {}", e))
                .await
            {
                eprintln!("Failed to log error: {}", log_err);
            }
            // Return parse error with null ID since we couldn't parse the message
            Ok(McpMessage::Error(McpError::parse_error(
                MessageId::Number(0),
                Some(serde_json::json!({"error": e.to_string()})),
            )))
        }
    }
}
