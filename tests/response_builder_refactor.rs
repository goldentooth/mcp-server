//! Tests for response builder refactoring
//!
//! This test module verifies that we can create reusable response builders
//! to eliminate duplication in JSON-RPC response construction

use goldentooth_mcp::types::{McpError, McpMessage, McpResponse, MessageId};
use serde_json::json;

#[test]
fn test_standard_error_responses() {
    let id = MessageId::Number(123);

    // Test common error patterns
    let parse_error = McpError::parse_error(id.clone(), None);
    let invalid_request = McpError::invalid_request(id.clone(), None);
    let method_not_found = McpError::method_not_found(id.clone(), None);
    let invalid_params = McpError::invalid_params(id.clone(), None);
    let internal_error = McpError::internal_error(id.clone(), None);

    // Verify they all have the correct structure
    assert_eq!(parse_error.error.code, -32700);
    assert_eq!(invalid_request.error.code, -32600);
    assert_eq!(method_not_found.error.code, -32601);
    assert_eq!(invalid_params.error.code, -32602);
    assert_eq!(internal_error.error.code, -32603);

    // All should have matching IDs
    assert_eq!(parse_error.id, id);
    assert_eq!(invalid_request.id, id);
    assert_eq!(method_not_found.id, id);
    assert_eq!(invalid_params.id, id);
    assert_eq!(internal_error.id, id);
}

#[test]
fn test_standard_success_responses() {
    let id = MessageId::String("test".to_string());

    // Test common success patterns
    let pong = McpResponse::pong(id.clone());
    let tools_list = McpResponse::tools_list_response(id.clone(), vec![]);
    let init_response = McpResponse::initialize_response(
        id.clone(),
        json!({"tools": []}),
        json!({"name": "test", "version": "1.0.0"}),
    );

    // Verify they all have the correct structure
    assert_eq!(pong.id, id);
    assert_eq!(tools_list.id, id);
    assert_eq!(init_response.id, id);

    // Verify JSON-RPC version is correct
    assert_eq!(pong.jsonrpc.to_string(), "2.0");
    assert_eq!(tools_list.jsonrpc.to_string(), "2.0");
    assert_eq!(init_response.jsonrpc.to_string(), "2.0");
}

#[test]
fn test_error_messages_serialization() {
    let id = MessageId::Number(1);
    let error = McpError::invalid_params(id, Some(json!({"param": "missing_required_field"})));

    let json_str = error.to_json_string().unwrap();

    // Should contain all required fields
    assert!(json_str.contains("\"jsonrpc\":\"2.0\""));
    assert!(json_str.contains("\"error\""));
    assert!(json_str.contains("\"code\":-32602"));
    assert!(json_str.contains("\"id\":1"));
}

#[test]
fn test_response_messages_serialization() {
    let id = MessageId::String("response_test".to_string());
    let response = McpResponse::new(json!({"result": "success"}), id);

    let json_str = response.to_json_string().unwrap();

    // Should contain all required fields
    assert!(json_str.contains("\"jsonrpc\":\"2.0\""));
    assert!(json_str.contains("\"result\""));
    assert!(json_str.contains("\"id\":\"response_test\""));
}

#[test]
fn test_message_wrapper_consistency() {
    let id = MessageId::Number(42);

    let response = McpMessage::Response(McpResponse::pong(id.clone()));
    let error = McpMessage::Error(McpError::internal_error(id.clone(), None));

    // Both should have consistent ID access
    assert_eq!(response.id(), &id);
    assert_eq!(error.id(), &id);

    // Both should serialize successfully
    assert!(response.to_json_string().is_ok());
    assert!(error.to_json_string().is_ok());
}
