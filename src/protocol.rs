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

    // Validate the request thoroughly before processing
    if let Err(validation_error) = validate_mcp_request(&req) {
        streams
            .log_warn_safe(&format!(
                "Request validation failed for {}: {}",
                req.method, validation_error
            ))
            .await;
        return McpMessage::Error(validation_error_to_mcp_error(
            validation_error,
            req.id.clone(),
        ));
    }

    match req.method {
        crate::types::McpMethod::Initialize => {
            // Generate capabilities dynamically from available tools
            let all_tools = tools::get_all_tools();
            let tool_names: Vec<&str> = all_tools.iter().map(|tool| tool.name()).collect();

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
            // Generate tool list dynamically from the tool trait implementations
            let all_tools = tools::get_all_tools();
            let tool_definitions: Vec<serde_json::Value> = all_tools
                .into_iter()
                .map(|tool| {
                    serde_json::json!({
                        "name": tool.name(),
                        "description": tool.description(),
                        "inputSchema": tool.input_schema()
                    })
                })
                .collect();

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
