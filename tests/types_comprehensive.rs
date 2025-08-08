//! Comprehensive tests for types modules to improve coverage
//!
//! These tests target uncovered paths in all types modules

use goldentooth_mcp::types::{
    ErrorCode, LogEntry, LogLevel, McpError, McpMessage, McpMethod, McpRequest, McpResponse,
    McpStreams, MessageId,
};
use serde_json::json;
use std::env;
use std::str::FromStr;

#[tokio::test]
async fn test_log_level_comprehensive() {
    // Test all log level variants
    assert_eq!(LogLevel::Trace.to_string(), "trace");
    assert_eq!(LogLevel::Debug.to_string(), "debug");
    assert_eq!(LogLevel::Info.to_string(), "info");
    assert_eq!(LogLevel::Warn.to_string(), "warn");
    assert_eq!(LogLevel::Error.to_string(), "error");

    // Test should_log for all combinations
    let levels = [
        LogLevel::Trace,
        LogLevel::Debug,
        LogLevel::Info,
        LogLevel::Warn,
        LogLevel::Error,
    ];
    for &message_level in &levels {
        for &threshold in &levels {
            let should_log = message_level.should_log(threshold);
            // should_log returns true if the message level >= threshold level
            // e.g., Error messages (level 4) should be logged when threshold is Info (level 2)
            // but Trace messages (level 0) should NOT be logged when threshold is Info (level 2)
            let expected = (message_level as i32) >= (threshold as i32);
            assert_eq!(
                should_log, expected,
                "Message level {message_level:?} should_log(threshold {threshold:?}) = {should_log}, expected {expected}"
            );
        }
    }

    // Test ordering
    assert!(LogLevel::Trace < LogLevel::Debug);
    assert!(LogLevel::Debug < LogLevel::Info);
    assert!(LogLevel::Info < LogLevel::Warn);
    assert!(LogLevel::Warn < LogLevel::Error);

    // Test from_str edge cases
    assert_eq!(LogLevel::from_str("TRACE").unwrap(), LogLevel::Trace);
    assert_eq!(LogLevel::from_str("Debug").unwrap(), LogLevel::Debug);
    assert_eq!(LogLevel::from_str("INFO").unwrap(), LogLevel::Info);
    assert_eq!(LogLevel::from_str("Warning").unwrap(), LogLevel::Warn); // Valid alias
    assert_eq!(LogLevel::from_str("err").unwrap(), LogLevel::Error); // Valid alias
    assert!(LogLevel::from_str("").is_err()); // Empty
    assert!(LogLevel::from_str("invalid").is_err());

    // Test from_env with different environment variables
    unsafe {
        env::set_var("TEST_LOG_LEVEL", "error");
    }
    let level = LogLevel::from_env("TEST_LOG_LEVEL");
    assert_eq!(level, LogLevel::Error);

    unsafe {
        env::set_var("TEST_LOG_LEVEL", "WARN");
    }
    let level = LogLevel::from_env("TEST_LOG_LEVEL");
    assert_eq!(level, LogLevel::Warn);

    unsafe {
        env::remove_var("TEST_LOG_LEVEL");
    }
    let level = LogLevel::from_env("TEST_LOG_LEVEL");
    assert_eq!(level, LogLevel::Info); // Default when missing

    unsafe {
        env::remove_var("TEST_LOG_LEVEL");
    }
}

#[test]
fn test_error_codes_comprehensive() {
    use goldentooth_mcp::types::{JsonRpcErrorCode, McpErrorCode};

    // Test JSON-RPC error codes
    assert_eq!(JsonRpcErrorCode::ParseError.code(), -32700);
    assert_eq!(JsonRpcErrorCode::InvalidRequest.code(), -32600);
    assert_eq!(JsonRpcErrorCode::MethodNotFound.code(), -32601);
    assert_eq!(JsonRpcErrorCode::InvalidParams.code(), -32602);
    assert_eq!(JsonRpcErrorCode::InternalError.code(), -32603);

    // Test from_code
    assert_eq!(
        JsonRpcErrorCode::from_code(-32700),
        Some(JsonRpcErrorCode::ParseError)
    );
    assert_eq!(
        JsonRpcErrorCode::from_code(-32600),
        Some(JsonRpcErrorCode::InvalidRequest)
    );
    assert_eq!(
        JsonRpcErrorCode::from_code(-32601),
        Some(JsonRpcErrorCode::MethodNotFound)
    );
    assert_eq!(
        JsonRpcErrorCode::from_code(-32602),
        Some(JsonRpcErrorCode::InvalidParams)
    );
    assert_eq!(
        JsonRpcErrorCode::from_code(-32603),
        Some(JsonRpcErrorCode::InternalError)
    );
    assert_eq!(JsonRpcErrorCode::from_code(123), None);

    // Test messages
    assert_eq!(JsonRpcErrorCode::ParseError.message(), "Parse error");
    assert_eq!(
        JsonRpcErrorCode::InvalidRequest.message(),
        "Invalid Request"
    );
    assert_eq!(
        JsonRpcErrorCode::MethodNotFound.message(),
        "Method not found"
    );
    assert_eq!(JsonRpcErrorCode::InvalidParams.message(), "Invalid params");
    assert_eq!(JsonRpcErrorCode::InternalError.message(), "Internal error");

    // Test MCP error codes
    assert_eq!(McpErrorCode::NodeUnreachable.code(), -32000);
    assert_eq!(McpErrorCode::AuthenticationFailed.code(), -32001);
    assert_eq!(McpErrorCode::ToolExecutionFailed.code(), -32002);
    assert_eq!(McpErrorCode::ConfigurationError.code(), -32003);
    assert_eq!(McpErrorCode::ResourceUnavailable.code(), -32004);
    assert_eq!(McpErrorCode::OperationTimeout.code(), -32005);

    // Test unified ErrorCode
    let json_error = ErrorCode::JsonRpc(JsonRpcErrorCode::ParseError);
    assert_eq!(json_error.code(), -32700);
    assert_eq!(json_error.message(), "Parse error");

    let mcp_error = ErrorCode::Mcp(McpErrorCode::NodeUnreachable);
    assert_eq!(mcp_error.code(), -32000);
    assert_eq!(mcp_error.message(), "Cluster node is unreachable");
}

#[test]
fn test_message_id_comprehensive() {
    // Test different message ID types
    let string_id = MessageId::String("test-id".to_string());
    let number_id = MessageId::Number(42);

    // Test serialization
    let string_json = serde_json::to_string(&string_id).unwrap();
    assert_eq!(string_json, r#""test-id""#);

    let number_json = serde_json::to_string(&number_id).unwrap();
    assert_eq!(number_json, "42");

    // Test deserialization
    let parsed_string: MessageId = serde_json::from_str(r#""test-id""#).unwrap();
    assert_eq!(parsed_string, string_id);

    let parsed_number: MessageId = serde_json::from_str("42").unwrap();
    assert_eq!(parsed_number, number_id);

    // Test Display
    assert_eq!(string_id.to_string(), "test-id");
    assert_eq!(number_id.to_string(), "42");

    // Test Clone and PartialEq
    assert_eq!(string_id.clone(), string_id);
    assert_eq!(number_id.clone(), number_id);
    assert_ne!(string_id, number_id);
}

#[test]
fn test_mcp_method_comprehensive() {
    use std::str::FromStr;

    // Test all method variants
    let methods = [
        (McpMethod::Initialize, "initialize"),
        (McpMethod::Ping, "ping"),
        (McpMethod::ToolsList, "tools/list"),
        (McpMethod::ToolsCall, "tools/call"),
        (McpMethod::ResourcesList, "resources/list"),
        (McpMethod::ResourcesRead, "resources/read"),
        (McpMethod::PromptsList, "prompts/list"),
        (McpMethod::PromptsGet, "prompts/get"),
    ];

    for (method, string_repr) in &methods {
        // Test Display
        assert_eq!(method.to_string(), *string_repr);

        // Test FromStr
        let parsed = McpMethod::from_str(string_repr).unwrap();
        assert_eq!(parsed, *method);

        // Test serialization/deserialization
        let json = serde_json::to_string(method).unwrap();
        let parsed: McpMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, *method);
    }

    // Test invalid method parsing
    assert!(McpMethod::from_str("invalid/method").is_err());
    assert!(McpMethod::from_str("").is_err());
}

#[tokio::test]
async fn test_mcp_streams_comprehensive() {
    let mut streams = McpStreams::new();

    // Test all log levels
    streams.log_trace("trace").await.unwrap();
    streams.log_debug("debug").await.unwrap();
    streams.log_info("info").await.unwrap();
    streams.log_warn("warn").await.unwrap();
    streams.log_error("error").await.unwrap();

    // Test that logs work - we can't test with_context methods if they don't exist
    // but we can test the basic logging functionality works

    // Test send_response
    let response = McpMessage::Response(McpResponse::pong(MessageId::Number(1)));
    streams.send_response(response).await.unwrap();
}

#[test]
fn test_log_entry_comprehensive() {
    use chrono::{DateTime, Utc};

    // Test basic log entry
    let entry = LogEntry::new(LogLevel::Info, "test message".to_string());
    assert_eq!(entry.level, LogLevel::Info);
    assert_eq!(entry.message, "test message");
    assert!(entry.context.is_none());

    // Test log entry with context
    let context = json!({"key": "value"});
    let entry = LogEntry::new_with_context(
        LogLevel::Error,
        "error message".to_string(),
        context.clone(),
    );
    assert_eq!(entry.level, LogLevel::Error);
    assert_eq!(entry.message, "error message");
    assert_eq!(entry.context, Some(context));

    // Test serialization
    let json_str = entry.to_json_string().unwrap();
    assert!(json_str.contains("error message"));
    assert!(json_str.contains("error"));
    assert!(json_str.contains("timestamp"));

    // Test that timestamp is valid
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    let timestamp_str = parsed["timestamp"].as_str().unwrap();
    let _parsed_time: DateTime<Utc> = timestamp_str.parse().unwrap();
}

#[test]
fn test_mcp_error_comprehensive() {
    // Test all error types
    let id = MessageId::Number(1);
    let data = Some(json!({"key": "value"}));

    // Test parse_error
    let error = McpError::parse_error(id.clone(), data.clone());
    let json = error.to_json_string().unwrap();
    assert!(json.contains("-32700"));
    assert!(json.contains("Parse error"));

    // Test invalid_request
    let error = McpError::invalid_request(id.clone(), data.clone());
    let json = error.to_json_string().unwrap();
    assert!(json.contains("-32600"));
    assert!(json.contains("Invalid Request"));

    // Test method_not_found
    let error = McpError::method_not_found(id.clone(), Some("method not found".to_string()));
    let json = error.to_json_string().unwrap();
    assert!(json.contains("-32601"));
    assert!(json.contains("Method not found"));

    // Test invalid_params
    let error = McpError::invalid_params(id.clone(), data.clone());
    let json = error.to_json_string().unwrap();
    assert!(json.contains("-32602"));
    assert!(json.contains("Invalid params"));

    // Test internal_error
    let error = McpError::internal_error(id.clone(), data.clone());
    let json = error.to_json_string().unwrap();
    assert!(json.contains("-32603"));
    assert!(json.contains("Internal error"));

    // Test serialization/deserialization
    let error = McpError::parse_error(MessageId::String("test".to_string()), None);
    let json = serde_json::to_string(&error).unwrap();
    let parsed: McpError = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.id, error.id);
    assert_eq!(parsed.error.code, error.error.code);
}

#[test]
fn test_mcp_response_comprehensive() {
    // Test basic response
    let response = McpResponse::new(json!({"result": "success"}), MessageId::Number(1));
    let json = response.to_json_string().unwrap();
    assert!(json.contains("success"));
    assert!(json.contains("\"id\":1"));

    // Test pong response
    let response = McpResponse::pong(MessageId::String("ping-test".to_string()));
    let json = response.to_json_string().unwrap();
    assert!(json.contains("\"result\":{}"));
    assert!(json.contains("ping-test"));

    // Test initialize response
    let response = McpResponse::initialize_response(
        MessageId::Number(2),
        json!({"tool1": "available"}),
        json!({"name": "server", "version": "1.0"}),
    );
    let json = response.to_json_string().unwrap();
    assert!(json.contains("tool1"));
    assert!(json.contains("server"));
    assert!(json.contains("\"id\":2"));

    // Test tools list response
    let tools = vec![
        json!({"name": "tool1", "description": "First tool"}),
        json!({"name": "tool2", "description": "Second tool"}),
    ];
    let response = McpResponse::tools_list_response(MessageId::Number(3), tools);
    let json = response.to_json_string().unwrap();
    assert!(json.contains("tool1"));
    assert!(json.contains("tool2"));
    assert!(json.contains("\"id\":3"));

    // Test serialization/deserialization
    let response = McpResponse::new(json!({"test": "data"}), MessageId::Number(4));
    let json = serde_json::to_string(&response).unwrap();
    let parsed: McpResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.id, response.id);
}

#[test]
fn test_mcp_request_comprehensive() {
    // Test request creation
    let request = McpRequest::new(
        McpMethod::Initialize,
        Some(json!({"test": "params"})),
        MessageId::String("init-1".to_string()),
    );

    assert_eq!(request.method, McpMethod::Initialize);
    assert_eq!(request.id, MessageId::String("init-1".to_string()));
    assert!(request.params.is_some());

    // Test serialization/deserialization
    let json = serde_json::to_string(&request).unwrap();
    let parsed: McpRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.method, request.method);
    assert_eq!(parsed.id, request.id);
    assert_eq!(parsed.params, request.params);

    // Test to_json_string
    let json_str = request.to_json_string().unwrap();
    assert!(json_str.contains("initialize"));
    assert!(json_str.contains("init-1"));
    assert!(json_str.contains("test"));
}

#[test]
fn test_mcp_message_comprehensive() {
    let request = McpRequest::new(McpMethod::Ping, None, MessageId::Number(1));
    let response = McpResponse::pong(MessageId::Number(2));
    let error = McpError::parse_error(MessageId::Number(3), None);

    // Test message wrapping
    let req_msg = McpMessage::Request(request);
    let resp_msg = McpMessage::Response(response);
    let err_msg = McpMessage::Error(error);

    // Test ID extraction
    assert_eq!(*req_msg.id(), MessageId::Number(1));
    assert_eq!(*resp_msg.id(), MessageId::Number(2));
    assert_eq!(*err_msg.id(), MessageId::Number(3));

    // Test JSON serialization
    let req_json = req_msg.to_json_string().unwrap();
    assert!(req_json.contains("ping"));
    assert!(req_json.contains("\"id\":1"));

    let resp_json = resp_msg.to_json_string().unwrap();
    assert!(resp_json.contains("\"result\":{}"));
    assert!(resp_json.contains("\"id\":2"));

    let err_json = err_msg.to_json_string().unwrap();
    assert!(err_json.contains("-32700"));
    assert!(err_json.contains("\"id\":3"));

    // Test from_json_str
    let parsed_req = McpMessage::from_json_str(&req_json).unwrap();
    assert_eq!(*parsed_req.id(), MessageId::Number(1));

    // Test invalid JSON
    assert!(McpMessage::from_json_str("invalid json").is_err());
    assert!(McpMessage::from_json_str("{}").is_err());
}

#[test]
fn test_error_handling_edge_cases() {
    // Test error with no data
    let error = McpError::method_not_found(MessageId::Number(1), None);
    let json = error.to_json_string().unwrap();
    assert!(!json.contains("data"));

    // Test error with empty string data
    let error = McpError::method_not_found(MessageId::Number(1), Some("".to_string()));
    let json = error.to_json_string().unwrap();
    assert!(json.contains("\"data\":{\"method\":\"\"}"));

    // Test various MessageId serialization in errors
    let string_id = MessageId::String("error-test".to_string());
    let error = McpError::invalid_request(string_id, None);
    let json = error.to_json_string().unwrap();
    assert!(json.contains("error-test"));
}
