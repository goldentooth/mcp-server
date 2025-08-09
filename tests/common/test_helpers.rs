//! Common test helpers to eliminate duplication across test files
//!
//! This module provides reusable utilities for test setup, request building,
//! response validation, and common assertions.

use goldentooth_mcp::protocol::process_json_request;
use goldentooth_mcp::types::{McpStreams, MessageId};
use serde_json::{Value, json};
use std::io::Cursor;

/// Test streams builder with common configurations
pub struct TestStreamsBuilder {
    log_level: Option<goldentooth_mcp::types::LogLevel>,
    capture_output: bool,
}

impl Default for TestStreamsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl TestStreamsBuilder {
    pub fn new() -> Self {
        Self {
            log_level: None,
            capture_output: false,
        }
    }

    pub fn with_log_level(mut self, level: goldentooth_mcp::types::LogLevel) -> Self {
        self.log_level = Some(level);
        self
    }

    pub fn capture_output(mut self) -> Self {
        self.capture_output = true;
        self
    }

    pub fn build(self) -> McpStreams {
        if self.capture_output {
            let stdout_buf = Vec::new();
            let stderr_buf = Vec::new();
            let log_level = self
                .log_level
                .unwrap_or(goldentooth_mcp::types::LogLevel::Error);
            McpStreams::new_with_writers_and_log_level(
                Cursor::new(stdout_buf),
                Cursor::new(stderr_buf),
                log_level,
            )
        } else if let Some(level) = self.log_level {
            McpStreams::new_with_log_level(level)
        } else {
            McpStreams::new()
        }
    }
}

/// JSON-RPC request builder with common patterns
pub struct JsonRpcRequestBuilder {
    method: String,
    id: Value,
    params: Option<Value>,
}

impl JsonRpcRequestBuilder {
    pub fn new(method: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            id: json!(1),
            params: None,
        }
    }

    pub fn with_id(mut self, id: impl Into<Value>) -> Self {
        self.id = id.into();
        self
    }

    pub fn with_params(mut self, params: Value) -> Self {
        self.params = Some(params);
        self
    }

    pub fn build(self) -> Value {
        let mut request = json!({
            "jsonrpc": "2.0",
            "method": self.method,
            "id": self.id
        });

        if let Some(params) = self.params {
            request["params"] = params;
        }

        request
    }
}

/// Common request builders for specific MCP methods
pub struct McpRequestBuilders;

#[allow(dead_code)]
impl McpRequestBuilders {
    pub fn initialize(id: impl Into<Value>) -> JsonRpcRequestBuilder {
        JsonRpcRequestBuilder::new("initialize")
            .with_id(id)
            .with_params(json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }))
    }

    pub fn ping(id: impl Into<Value>) -> JsonRpcRequestBuilder {
        JsonRpcRequestBuilder::new("ping").with_id(id)
    }

    pub fn tools_list(id: impl Into<Value>) -> JsonRpcRequestBuilder {
        JsonRpcRequestBuilder::new("tools/list")
            .with_id(id)
            .with_params(json!({}))
    }

    pub fn tools_call(id: impl Into<Value>, tool_name: &str, args: Value) -> JsonRpcRequestBuilder {
        JsonRpcRequestBuilder::new("tools/call")
            .with_id(id)
            .with_params(json!({
                "name": tool_name,
                "arguments": args
            }))
    }

    pub fn resources_list(id: impl Into<Value>) -> JsonRpcRequestBuilder {
        JsonRpcRequestBuilder::new("resources/list")
            .with_id(id)
            .with_params(json!({}))
    }

    pub fn prompts_list(id: impl Into<Value>) -> JsonRpcRequestBuilder {
        JsonRpcRequestBuilder::new("prompts/list")
            .with_id(id)
            .with_params(json!({}))
    }
}

/// Common MessageId builders
pub struct MessageIds;

#[allow(dead_code)]
impl MessageIds {
    pub fn number(n: u64) -> MessageId {
        MessageId::Number(n)
    }

    pub fn string(s: impl Into<String>) -> MessageId {
        MessageId::String(s.into())
    }

    pub fn test_id() -> MessageId {
        MessageId::String("test".to_string())
    }

    pub fn sequential(n: u64) -> MessageId {
        MessageId::Number(n)
    }
}

/// Response assertions helper
pub struct ResponseAssertions;

#[allow(dead_code)]
impl ResponseAssertions {
    /// Assert basic JSON-RPC 2.0 response structure
    pub fn assert_jsonrpc_response(response: &Value, expected_id: impl Into<Value>) {
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], expected_id.into());
    }

    /// Assert successful response with result
    pub fn assert_success_response(response: &Value, expected_id: impl Into<Value>) {
        Self::assert_jsonrpc_response(response, expected_id);
        // Success response must have a result field (any valid JSON type is acceptable)
        assert!(
            response.get("result").is_some(),
            "Success response must have a result field"
        );
        // Success response must not have an error field
        assert!(
            response.get("error").is_none(),
            "Success response must not have an error field"
        );
    }

    /// Assert error response with specific code
    pub fn assert_error_response(
        response: &Value,
        expected_id: impl Into<Value>,
        expected_code: i32,
    ) {
        Self::assert_jsonrpc_response(response, expected_id);
        assert!(response["error"].is_object());
        assert_eq!(response["error"]["code"], expected_code);
        assert!(response.get("result").is_none());
    }

    /// Assert tools list response structure
    pub fn assert_tools_list_response(response: &Value, expected_id: impl Into<Value>) {
        Self::assert_success_response(response, expected_id);
        assert!(response["result"]["tools"].is_array());

        let tools = response["result"]["tools"].as_array().unwrap();
        for tool in tools {
            assert!(tool["name"].is_string());
            assert!(tool["description"].is_string());
            assert!(tool["inputSchema"].is_object());
        }
    }

    /// Assert initialization response structure
    pub fn assert_initialize_response(response: &Value, expected_id: impl Into<Value>) {
        Self::assert_success_response(response, expected_id);
        assert!(response["result"]["capabilities"].is_object());
        assert!(response["result"]["serverInfo"].is_object());
        assert_eq!(response["result"]["protocolVersion"], "2025-06-18");
    }
}

/// MCP request processor with shared setup
pub struct McpRequestProcessor {
    streams: McpStreams,
}

#[allow(dead_code)]
impl McpRequestProcessor {
    pub fn new() -> Self {
        Self {
            streams: TestStreamsBuilder::new().capture_output().build(),
        }
    }

    pub fn with_streams(streams: McpStreams) -> Self {
        Self { streams }
    }

    /// Process a JSON-RPC request and return the response
    pub async fn process(&mut self, request: Value) -> Result<Value, String> {
        let request_str = request.to_string();
        let response_result = process_json_request(&request_str, &mut self.streams).await;

        match response_result {
            Ok(response) => Ok(serde_json::from_str(&response.to_json_string().unwrap())
                .expect("Response should be valid JSON")),
            Err(e) => Err(e),
        }
    }

    /// Process a request and assert it succeeds
    pub async fn process_success(
        &mut self,
        request: Value,
        expected_id: impl Into<Value>,
    ) -> Value {
        let response = self
            .process(request)
            .await
            .expect("Request should process successfully");
        ResponseAssertions::assert_success_response(&response, expected_id);
        response
    }

    /// Process a request and assert it fails with specific error code
    pub async fn process_error(
        &mut self,
        request: Value,
        expected_id: impl Into<Value>,
        expected_code: i32,
    ) -> Value {
        let response = self
            .process(request)
            .await
            .expect("Request should process successfully");
        ResponseAssertions::assert_error_response(&response, expected_id, expected_code);
        response
    }
}

impl Default for McpRequestProcessor {
    fn default() -> Self {
        Self::new()
    }
}

/// Test data generators for common scenarios
#[allow(dead_code)]
pub struct TestDataGenerators;

#[allow(dead_code)]
impl TestDataGenerators {
    /// Generate invalid JSON strings for error testing
    pub fn invalid_json_strings() -> Vec<&'static str> {
        vec![
            "invalid json",
            "{incomplete",
            "[1,2,3",
            "null",
            "",
            "not json at all",
            "{'invalid': quotes}",
            "{\"unterminated\": string",
        ]
    }

    /// Generate invalid method names for testing
    pub fn invalid_method_names() -> Vec<&'static str> {
        vec![
            "",
            "invalid",
            "INITIALIZE", // wrong case
            "tools/CALL", // wrong case
            "unknown/method",
            "tools/list/extra",
            "123invalid",
        ]
    }

    /// Generate test tool names that are known to work without required parameters
    pub fn test_tool_names() -> Vec<&'static str> {
        vec![
            "cluster_ping", // This is the only tool confirmed to work without params
        ]
    }

    /// Generate all available tool names (including ones that might need params or not be implemented)
    pub fn all_tool_names() -> Vec<&'static str> {
        vec![
            "cluster_ping",
            "cluster_status",
            "service_status",
            "resource_usage",
            "cluster_info",
        ]
    }

    /// Generate invalid tool names
    pub fn invalid_tool_names() -> Vec<&'static str> {
        vec!["nonexistent_tool", "invalid-tool", "", "123invalid"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_request_builder() {
        let request = JsonRpcRequestBuilder::new("test_method")
            .with_id(42)
            .with_params(json!({"key": "value"}))
            .build();

        assert_eq!(request["jsonrpc"], "2.0");
        assert_eq!(request["method"], "test_method");
        assert_eq!(request["id"], 42);
        assert_eq!(request["params"]["key"], "value");
    }

    #[tokio::test]
    async fn test_mcp_request_builders() {
        let ping = McpRequestBuilders::ping(1).build();
        assert_eq!(ping["method"], "ping");
        assert_eq!(ping["id"], 1);

        let tools_call = McpRequestBuilders::tools_call(2, "test_tool", json!({})).build();
        assert_eq!(tools_call["method"], "tools/call");
        assert_eq!(tools_call["params"]["name"], "test_tool");
    }

    #[test]
    fn test_message_ids() {
        let num_id = MessageIds::number(123);
        assert_eq!(num_id, MessageId::Number(123));

        let str_id = MessageIds::string("test");
        assert_eq!(str_id, MessageId::String("test".to_string()));
    }

    #[test]
    fn test_response_assertions() {
        let success_response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {}
        });
        ResponseAssertions::assert_success_response(&success_response, 1);

        let error_response = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "error": {
                "code": -32601,
                "message": "Method not found"
            }
        });
        ResponseAssertions::assert_error_response(&error_response, 2, -32601);
    }
}
