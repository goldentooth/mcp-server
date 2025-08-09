//! Demonstration of DRY error handling patterns using test helpers

mod common;
use common::test_helpers::{TestDataGenerators, TestStreamsBuilder};
use common::{McpRequestBuilders, McpRequestProcessor};
use goldentooth_mcp::types::LogLevel;
use serde_json::json;

#[tokio::test]
async fn test_invalid_json_parsing_with_helpers() {
    let mut processor = McpRequestProcessor::new();

    // Use helper to get standard invalid JSON strings
    for invalid_json in TestDataGenerators::invalid_json_strings() {
        // Process raw string - these should all fail parsing
        let result = processor.process(json!(invalid_json)).await;
        assert!(
            result.is_err(),
            "Invalid JSON '{invalid_json}' should fail parsing"
        );
    }
}

#[tokio::test]
async fn test_invalid_method_names_with_helpers() {
    let mut processor = McpRequestProcessor::new();

    // Use helper to get standard invalid method names
    for invalid_method in TestDataGenerators::invalid_method_names() {
        let request = json!({
            "jsonrpc": "2.0",
            "method": invalid_method,
            "id": 1
        });

        let result = processor.process(request).await;
        assert!(
            result.is_err(),
            "Invalid method '{invalid_method}' should fail"
        );
    }
}

#[tokio::test]
async fn test_invalid_tool_names_with_helpers() {
    let mut processor = McpRequestProcessor::new();

    for invalid_tool in TestDataGenerators::invalid_tool_names() {
        let request = McpRequestBuilders::tools_call(1, invalid_tool, json!({})).build();

        // Invalid tools should return error responses (not parsing failures)
        let response = processor.process_error(request, 1, -32602).await;

        // Verify error contains information about invalid tool
        let error_data = &response["error"]["data"];
        assert!(
            error_data["error"]
                .as_str()
                .unwrap_or("")
                .contains("unsupported tool")
                || error_data["error"]
                    .as_str()
                    .unwrap_or("")
                    .contains(invalid_tool),
            "Error should mention invalid tool '{invalid_tool}', got: {error_data:?}"
        );
    }
}

#[tokio::test]
async fn test_valid_tools_with_helpers() {
    let mut processor = McpRequestProcessor::new();

    for valid_tool in TestDataGenerators::test_tool_names() {
        let request = McpRequestBuilders::tools_call(1, valid_tool, json!({})).build();

        // Valid tools should succeed (even if they return mock data)
        let response = processor.process_success(request, 1).await;

        // Should have result field (any valid JSON type)
        assert!(
            response.get("result").is_some(),
            "Tool '{valid_tool}' should return result field"
        );
    }
}

#[tokio::test]
async fn test_logging_patterns_with_helpers() {
    // Create streams with debug logging enabled
    let streams = TestStreamsBuilder::new()
        .with_log_level(LogLevel::Debug)
        .capture_output()
        .build();

    let mut processor = McpRequestProcessor::with_streams(streams);

    // Process various requests - all should have debug logging
    let requests = vec![
        McpRequestBuilders::ping(1).build(),
        McpRequestBuilders::tools_list(2).build(),
        McpRequestBuilders::initialize(3).build(),
    ];

    for request in requests {
        let _response = processor
            .process(request)
            .await
            .expect("Valid requests should process successfully");
        // Debug logging would be captured in the streams (not verified here for simplicity)
    }
}

#[tokio::test]
async fn test_multiple_error_conditions() {
    let mut processor = McpRequestProcessor::new();

    // Test various error conditions using builders
    let error_cases = vec![
        // Missing params
        (
            json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "id": 1
                // Missing params
            }),
            -32602,
        ), // Invalid params
        // Invalid params structure
        (
            json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "id": 2,
                "params": {
                    // Missing required 'name' parameter
                    "arguments": {}
                }
            }),
            -32602,
        ), // Invalid params
    ];

    for (request, expected_code) in error_cases {
        let id = request["id"].clone();
        let response = processor.process_error(request, id, expected_code).await;

        // All error responses should have proper structure
        assert!(response["error"]["message"].is_string());
        assert!(response["error"]["code"].is_number());
    }
}

/// Demonstration of how much simpler tests become with helpers
#[tokio::test]
async fn test_before_and_after_comparison() {
    // BEFORE (traditional approach with lots of duplication):
    /*
    let mut streams = McpStreams::new();
    let request_str = r#"{"jsonrpc":"2.0","method":"ping","id":1}"#;
    let response = process_json_request(request_str, &mut streams).await.unwrap();
    let parsed: Value = serde_json::from_str(&response.to_json_string().unwrap()).unwrap();
    assert_eq!(parsed["jsonrpc"], "2.0");
    assert_eq!(parsed["id"], 1);
    assert!(parsed["result"].is_object());
    */

    // AFTER (using helpers - much cleaner):
    let mut processor = McpRequestProcessor::new();
    let request = McpRequestBuilders::ping(1).build();
    processor.process_success(request, 1).await;

    // The helper handles all the boilerplate:
    // - Stream creation
    // - JSON serialization/deserialization
    // - Response parsing
    // - Standard assertions
    // - Error handling
}
