//! Unit tests for main.rs functions
//!
//! These tests specifically target the CLI handling and main loop functions
//! that are typically not covered by integration tests.

use goldentooth_mcp::main_functions::{handle_help, handle_invalid_arg, handle_version};
use goldentooth_mcp::types::{LogLevel, McpStreams};
use std::env;

// Helper to capture stdout output during testing
#[tokio::test]
async fn test_handle_version_output() {
    // Version info should include package name and version
    let mut streams = McpStreams::new();

    // This will print to stdout in the test environment
    let result = handle_version(&mut streams).await;
    assert!(result.is_ok(), "Version handler should succeed");

    // We can't easily capture stdout in this test setup,
    // but we can verify the function completes successfully
}

#[tokio::test]
async fn test_handle_help_output() {
    let mut streams = McpStreams::new();

    let result = handle_help(&mut streams).await;
    assert!(result.is_ok(), "Help handler should succeed");
}

#[tokio::test]
async fn test_handle_invalid_arg() {
    let mut streams = McpStreams::new();

    let result = handle_invalid_arg(&mut streams, "--unknown").await;
    assert!(result.is_ok(), "Invalid arg handler should succeed");
}

#[tokio::test]
async fn test_log_level_from_env() {
    // Test default case
    unsafe {
        env::remove_var("MCP_LOG_LEVEL");
    }
    let default_level = LogLevel::from_env("MCP_LOG_LEVEL");
    assert_eq!(default_level, LogLevel::Info);

    // Test explicit setting
    unsafe {
        env::set_var("MCP_LOG_LEVEL", "debug");
    }
    let debug_level = LogLevel::from_env("MCP_LOG_LEVEL");
    assert_eq!(debug_level, LogLevel::Debug);

    // Test case insensitive
    unsafe {
        env::set_var("MCP_LOG_LEVEL", "ERROR");
    }
    let error_level = LogLevel::from_env("MCP_LOG_LEVEL");
    assert_eq!(error_level, LogLevel::Error);

    // Test invalid value (should default to Info)
    unsafe {
        env::set_var("MCP_LOG_LEVEL", "invalid");
    }
    let invalid_level = LogLevel::from_env("MCP_LOG_LEVEL");
    assert_eq!(invalid_level, LogLevel::Info);

    // Clean up
    unsafe {
        env::remove_var("MCP_LOG_LEVEL");
    }
}

#[tokio::test]
async fn test_stream_initialization() {
    let streams = McpStreams::new();

    // Streams should be created successfully
    // Test logging at different levels
    let mut test_streams = streams;

    let result = test_streams.log_trace("trace message").await;
    assert!(result.is_ok());

    let result = test_streams.log_debug("debug message").await;
    assert!(result.is_ok());

    let result = test_streams.log_info("info message").await;
    assert!(result.is_ok());

    let result = test_streams.log_warn("warn message").await;
    assert!(result.is_ok());

    let result = test_streams.log_error("error message").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_consecutive_error_counting() {
    // Test that we can handle the circuit breaker logic
    let mut streams = McpStreams::new();
    let max_consecutive_errors = 5;

    // Simulate error counting behavior
    let mut consecutive_errors = 0;

    // Process multiple invalid JSON requests to test error counting
    let invalid_requests = [
        "invalid json",
        "{incomplete",
        "[1,2,3",
        "null",
        "",
        "not json at all",
    ];

    for invalid_request in &invalid_requests {
        let result =
            goldentooth_mcp::protocol::process_json_request(invalid_request, &mut streams).await;

        match result {
            Ok(_) => consecutive_errors = 0,
            Err(_) => {
                consecutive_errors += 1;
                if consecutive_errors >= max_consecutive_errors {
                    // Would break in real implementation
                    break;
                }
            }
        }
    }

    // Verify we incremented error count correctly
    assert_eq!(consecutive_errors, max_consecutive_errors);
}

#[tokio::test]
async fn test_error_response_with_id_extraction() {
    use goldentooth_mcp::types::{McpError, McpMessage, MessageId};
    use serde_json;

    let _streams = McpStreams::new();

    // Test JSON that parses but has invalid structure (this path is tested in main loop)
    let partial_json = r#"{"jsonrpc": "2.0", "id": 123, "invalid": true}"#;

    // Try to parse as generic JSON to extract ID (simulating main loop logic)
    if let Ok(parsed_json) = serde_json::from_str::<serde_json::Value>(partial_json) {
        if let Some(id_value) = parsed_json.get("id") {
            let id = if let Some(num) = id_value.as_u64() {
                MessageId::Number(num)
            } else if let Some(s) = id_value.as_str() {
                MessageId::String(s.to_string())
            } else {
                MessageId::Number(0)
            };

            // Should be able to create error response with extracted ID
            let error_response = McpMessage::Error(McpError::invalid_request(
                id,
                Some(serde_json::json!({"error": "Request processing failed"})),
            ));

            let json_str = error_response.to_json_string().unwrap();
            assert!(
                json_str.contains("123"),
                "Error response should include original ID"
            );
        }
    }
}

#[tokio::test]
async fn test_stream_send_response() {
    use goldentooth_mcp::types::{McpMessage, McpResponse, MessageId};

    let mut streams = McpStreams::new();

    // Test sending a response through streams
    let response = McpMessage::Response(McpResponse::pong(MessageId::Number(1)));

    let result = streams.send_response(response).await;
    assert!(
        result.is_ok(),
        "Should be able to send response through streams"
    );
}

#[tokio::test]
async fn test_empty_line_handling() {
    let _streams = McpStreams::new();

    // Empty lines should be skipped - test the trim logic
    let empty_lines = ["", "   ", "\t", "\n", "  \t  \n"];

    for empty_line in &empty_lines {
        let trimmed = empty_line.trim();
        assert!(
            trimmed.is_empty(),
            "Should identify empty line: '{empty_line}'"
        );
    }

    // Non-empty line should not be skipped
    let non_empty = "  {\"jsonrpc\": \"2.0\"}  ";
    let trimmed = non_empty.trim();
    assert!(!trimmed.is_empty(), "Should identify non-empty line");
}

#[tokio::test]
async fn test_stdin_line_processing_simulation() {
    use goldentooth_mcp::protocol::process_json_request;

    let mut streams = McpStreams::new();

    // Simulate processing different types of lines that would come from stdin
    let test_lines = [
        // Valid MCP message
        r#"{"jsonrpc": "2.0", "method": "ping", "id": 1}"#,
        // Invalid JSON
        "not json",
        // Empty object
        "{}",
        // Partial JSON
        r#"{"jsonrpc": "2.0""#,
    ];

    let mut results = Vec::new();

    for line in &test_lines {
        if !line.trim().is_empty() {
            let result = process_json_request(line, &mut streams).await;
            results.push(result.is_ok());
        }
    }

    // First line should succeed, others should fail
    assert_eq!(results, [true, false, false, false]);
}
