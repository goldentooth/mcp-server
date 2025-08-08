//! MCP Message types that guarantee JSON-RPC 2.0 compliance
//!
//! These types make it impossible to create invalid MCP messages.
//! All messages are guaranteed to have the correct structure and version.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::{self, Display, Formatter};

/// JSON-RPC version - only 2.0 is supported
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JsonRpcVersion {
    #[serde(rename = "2.0")]
    V2_0,
}

impl Display for JsonRpcVersion {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "2.0")
    }
}

impl Default for JsonRpcVersion {
    fn default() -> Self {
        Self::V2_0
    }
}

/// Message ID for request/response correlation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageId {
    Number(u64),
    String(String),
}

impl Display for MessageId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            MessageId::Number(n) => write!(f, "{}", n),
            MessageId::String(s) => write!(f, "{}", s),
        }
    }
}

/// MCP method names - constrained to valid methods
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpMethod {
    #[serde(rename = "initialize")]
    Initialize,
    #[serde(rename = "notifications/ping")]
    Ping,
    #[serde(rename = "tools/list")]
    ToolsList,
    #[serde(rename = "tools/call")]
    ToolsCall,
    #[serde(rename = "resources/list")]
    ResourcesList,
    #[serde(rename = "resources/read")]
    ResourcesRead,
    #[serde(rename = "prompts/list")]
    PromptsList,
    #[serde(rename = "prompts/get")]
    PromptsGet,
}

impl Display for McpMethod {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let method_str = match self {
            McpMethod::Initialize => "initialize",
            McpMethod::Ping => "notifications/ping",
            McpMethod::ToolsList => "tools/list",
            McpMethod::ToolsCall => "tools/call",
            McpMethod::ResourcesList => "resources/list",
            McpMethod::ResourcesRead => "resources/read",
            McpMethod::PromptsList => "prompts/list",
            McpMethod::PromptsGet => "prompts/get",
        };
        write!(f, "{}", method_str)
    }
}

/// Request message content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRequest {
    pub jsonrpc: JsonRpcVersion,
    pub method: McpMethod,
    pub params: Option<Value>,
    pub id: MessageId,
}

impl McpRequest {
    pub fn new(method: McpMethod, params: Option<Value>, id: MessageId) -> Self {
        Self {
            jsonrpc: JsonRpcVersion::V2_0,
            method,
            params,
            id,
        }
    }

    /// Serialize to JSON string for transmission
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn initialize(
        id: MessageId,
        protocol_version: String,
        capabilities: Value,
        client_info: Value,
    ) -> Self {
        Self::new(
            McpMethod::Initialize,
            Some(serde_json::json!({
                "protocolVersion": protocol_version,
                "capabilities": capabilities,
                "clientInfo": client_info
            })),
            id,
        )
    }

    pub fn ping(id: MessageId) -> Self {
        Self::new(McpMethod::Ping, None, id)
    }

    pub fn tools_list(id: MessageId) -> Self {
        Self::new(McpMethod::ToolsList, Some(serde_json::json!({})), id)
    }
}

/// Success response content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResponse {
    pub jsonrpc: JsonRpcVersion,
    pub result: Value,
    pub id: MessageId,
}

impl McpResponse {
    pub fn new(result: Value, id: MessageId) -> Self {
        Self {
            jsonrpc: JsonRpcVersion::V2_0,
            result,
            id,
        }
    }

    /// Serialize to JSON string for transmission
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn initialize_response(id: MessageId, capabilities: Value, server_info: Value) -> Self {
        Self::new(
            serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": capabilities,
                "serverInfo": server_info
            }),
            id,
        )
    }

    pub fn pong(id: MessageId) -> Self {
        Self::new(serde_json::json!({}), id)
    }

    pub fn tools_list_response(id: MessageId, tools: Vec<Value>) -> Self {
        Self::new(serde_json::json!({"tools": tools}), id)
    }
}

/// Error response content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpError {
    pub jsonrpc: JsonRpcVersion,
    pub error: JsonRpcErrorDetail,
    pub id: MessageId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcErrorDetail {
    pub code: i32,
    pub message: String,
    pub data: Option<Value>,
}

impl McpError {
    pub fn new(code: i32, message: String, data: Option<Value>, id: MessageId) -> Self {
        Self {
            jsonrpc: JsonRpcVersion::V2_0,
            error: JsonRpcErrorDetail {
                code,
                message,
                data,
            },
            id,
        }
    }

    /// Serialize to JSON string for transmission
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn parse_error(id: MessageId, details: Option<Value>) -> Self {
        Self::new(-32700, "Parse error".to_string(), details, id)
    }

    pub fn invalid_request(id: MessageId, details: Option<Value>) -> Self {
        Self::new(-32600, "Invalid Request".to_string(), details, id)
    }

    pub fn method_not_found(id: MessageId, method: Option<String>) -> Self {
        let data = method.map(|m| serde_json::json!({"method": m}));
        Self::new(-32601, "Method not found".to_string(), data, id)
    }

    pub fn invalid_params(id: MessageId, details: Option<Value>) -> Self {
        Self::new(-32602, "Invalid params".to_string(), details, id)
    }

    pub fn internal_error(id: MessageId, details: Option<Value>) -> Self {
        Self::new(-32603, "Internal error".to_string(), details, id)
    }
}

/// Top-level MCP message type - can only be one of these three
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum McpMessage {
    Request(McpRequest),
    Response(McpResponse),
    Error(McpError),
}

impl McpMessage {
    /// Get the message ID for correlation
    pub fn id(&self) -> &MessageId {
        match self {
            McpMessage::Request(req) => &req.id,
            McpMessage::Response(resp) => &resp.id,
            McpMessage::Error(err) => &err.id,
        }
    }

    /// Serialize to JSON string for transmission
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Parse from JSON string with validation
    pub fn from_json_str(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_request_serialize() {
        let request = McpRequest::ping(MessageId::Number(1));
        let json = request.to_json_string().unwrap();

        // Should contain required fields
        assert!(json.contains(r#""jsonrpc":"2.0""#));
        assert!(json.contains(r#""method":"notifications/ping""#));
        assert!(json.contains(r#""id":1"#));
    }

    #[test]
    fn test_mcp_response_serialize() {
        let response = McpResponse::pong(MessageId::Number(1));
        let json = response.to_json_string().unwrap();

        // Should contain required fields
        assert!(json.contains(r#""jsonrpc":"2.0""#));
        // Check for result field (might have whitespace differences)
        assert!(json.contains(r#""result":"#));
        assert!(json.contains(r#""id":1"#));
    }

    #[test]
    fn test_mcp_error_serialize() {
        let error = McpError::method_not_found(MessageId::Number(1), Some("unknown".to_string()));
        let json = error.to_json_string().unwrap();

        // Should contain required fields
        assert!(json.contains(r#""jsonrpc":"2.0""#));
        assert!(json.contains(r#""error""#));
        assert!(json.contains(r#""code":-32601"#));
        assert!(json.contains(r#""id":1"#));
    }

    #[test]
    fn test_message_roundtrip() {
        let original = McpMessage::Request(McpRequest::ping(MessageId::String("test".to_string())));
        let json = original.to_json_string().unwrap();
        let parsed = McpMessage::from_json_str(&json).unwrap();

        assert_eq!(original.id(), parsed.id());
    }
}
