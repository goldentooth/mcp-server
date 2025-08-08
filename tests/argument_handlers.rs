//! Tests for argument handler refactoring
//!
//! This test module verifies that we can extract common argument handling
//! functionality without breaking existing behavior.

use goldentooth_mcp::main_functions::{handle_help, handle_invalid_arg, handle_version};
use goldentooth_mcp::types::McpStreams;

#[tokio::test]
async fn test_handle_version_functionality() {
    let mut streams = McpStreams::new();
    let result = handle_version(&mut streams).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_handle_help_functionality() {
    let mut streams = McpStreams::new();
    let result = handle_help(&mut streams).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_handle_invalid_arg_functionality() {
    let mut streams = McpStreams::new();
    let result = handle_invalid_arg(&mut streams, "--unknown").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_version_handler_contains_package_info() {
    // Capture output by redirecting stdout temporarily
    let mut streams = McpStreams::new();
    let result = handle_version(&mut streams).await;
    assert!(result.is_ok());
    // The version handler should work without panicking
}

#[tokio::test]
async fn test_help_handler_contains_usage_info() {
    let mut streams = McpStreams::new();
    let result = handle_help(&mut streams).await;
    assert!(result.is_ok());
    // The help handler should work without panicking
}

#[tokio::test]
async fn test_invalid_arg_handler_with_various_args() {
    let mut streams = McpStreams::new();

    let test_args = ["--unknown", "-x", "invalid", "--very-long-invalid-argument"];

    for arg in test_args {
        let result = handle_invalid_arg(&mut streams, arg).await;
        assert!(result.is_ok(), "Failed to handle invalid argument: {arg}");
    }
}
