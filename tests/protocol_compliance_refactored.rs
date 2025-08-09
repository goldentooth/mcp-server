//! Protocol compliance tests using DRY helpers
//!
//! This demonstrates how to use the test helpers to eliminate duplication

mod common;
use common::test_helpers::ResponseAssertions;
use common::{McpRequestBuilders, McpRequestProcessor};
use serde_json::json;

#[tokio::test]
async fn test_initialize_handshake() {
    let mut processor = McpRequestProcessor::new();
    let request = McpRequestBuilders::initialize(1).build();

    let response = processor.process_success(request, 1).await;
    ResponseAssertions::assert_initialize_response(&response, 1);
}

#[tokio::test]
async fn test_ping_pong() {
    let mut processor = McpRequestProcessor::new();
    let request = McpRequestBuilders::ping(2).build();

    let response = processor.process_success(request, 2).await;
    // Ping response is just empty object
    assert!(response["result"].is_object());
}

#[tokio::test]
async fn test_tools_list() {
    let mut processor = McpRequestProcessor::new();
    let request = McpRequestBuilders::tools_list(3).build();

    let response = processor.process_success(request, 3).await;
    ResponseAssertions::assert_tools_list_response(&response, 3);

    // Verify we have at least one tool (cluster_ping)
    let tools = response["result"]["tools"].as_array().unwrap();
    assert!(!tools.is_empty(), "Should have at least one tool");
}

#[tokio::test]
async fn test_resources_list_not_implemented() {
    let mut processor = McpRequestProcessor::new();
    let request = McpRequestBuilders::resources_list(4).build();

    let response = processor.process_success(request, 4).await;
    // Should return empty resources list
    assert_eq!(response["result"]["resources"], json!([]));
}

#[tokio::test]
async fn test_prompts_list_not_implemented() {
    let mut processor = McpRequestProcessor::new();
    let request = McpRequestBuilders::prompts_list(5).build();

    let response = processor.process_success(request, 5).await;
    // Should return empty prompts list
    assert_eq!(response["result"]["prompts"], json!([]));
}

#[tokio::test]
async fn test_invalid_method() {
    let mut processor = McpRequestProcessor::new();
    let request = json!({
        "jsonrpc": "2.0",
        "method": "invalid_method",
        "id": 6
    });

    // Invalid methods cause parsing failures in our current enum setup
    let result = processor.process(request).await;
    assert!(
        result.is_err(),
        "Invalid method should cause processing to fail"
    );
}

#[tokio::test]
async fn test_tools_call_cluster_ping() {
    let mut processor = McpRequestProcessor::new();
    let request = McpRequestBuilders::tools_call(7, "cluster_ping", json!({})).build();

    let response = processor.process_success(request, 7).await;

    // Should have cluster ping results
    assert!(response["result"]["nodes"].is_object());
}

#[tokio::test]
async fn test_tools_call_invalid_tool() {
    let mut processor = McpRequestProcessor::new();
    let request = McpRequestBuilders::tools_call(8, "nonexistent_tool", json!({})).build();

    processor.process_error(request, 8, -32602).await; // Invalid params (validation fails)
}
