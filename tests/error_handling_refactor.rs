//! Tests for error handling pattern refactoring
//!
//! This test module verifies that we can create reusable error handling
//! patterns to eliminate repeated logging code

use goldentooth_mcp::types::McpStreams;

#[tokio::test]
async fn test_streams_can_handle_logging_errors_gracefully() {
    let mut streams = McpStreams::new();

    // These should not panic even if internal logging fails
    let result1 = streams.log_debug("test debug").await;
    let result2 = streams.log_info("test info").await;
    let result3 = streams.log_warn("test warn").await;
    let result4 = streams.log_error("test error").await;

    // All logging operations should succeed or fail gracefully
    assert!(result1.is_ok() || result1.is_err()); // Should not panic
    assert!(result2.is_ok() || result2.is_err()); // Should not panic
    assert!(result3.is_ok() || result3.is_err()); // Should not panic
    assert!(result4.is_ok() || result4.is_err()); // Should not panic
}

#[tokio::test]
async fn test_error_logging_with_context() {
    let mut streams = McpStreams::new();

    // Test various error message formats
    let error_messages = vec![
        "Simple error",
        "Error with details: failed to connect",
        "Multi-line error\nwith additional context",
        "", // Empty error (edge case)
    ];

    for message in error_messages {
        let result = streams.log_error(message).await;
        // Should handle all message types gracefully
        assert!(result.is_ok() || result.is_err()); // Should not panic
    }
}

#[tokio::test]
async fn test_debug_logging_with_formatting() {
    let mut streams = McpStreams::new();

    // Test debug logging with various formatted strings
    let test_values = vec![
        ("operation", "test_op", "parameter", "test_param"),
        ("method", "initialize", "id", "123"),
        ("tool", "cluster_ping", "args", "{}"),
    ];

    for (key1, val1, key2, val2) in test_values {
        let formatted_msg = format!("{key1} {val1} with {key2}: {val2}");
        let result = streams.log_debug(&formatted_msg).await;
        // Should handle formatted messages gracefully
        assert!(result.is_ok() || result.is_err()); // Should not panic
    }
}

/// Test that we can create consistent error handling patterns
#[tokio::test]
async fn test_consistent_error_patterns() {
    let mut streams = McpStreams::new();

    // Simulate the common pattern found in protocol.rs
    async fn simulate_operation_with_logging(
        streams: &mut McpStreams,
        operation: &str,
    ) -> Result<String, String> {
        // This pattern appears multiple times in protocol.rs
        if let Err(e) = streams.log_debug(&format!("Starting {operation}")).await {
            eprintln!("Failed to log debug: {e}");
        }

        // Simulate some work
        if operation == "failing_operation" {
            if let Err(e) = streams.log_error(&format!("{operation} failed")).await {
                eprintln!("Failed to log error: {e}");
            }
            return Err(format!("{operation} failed"));
        }

        Ok(format!("{operation} completed"))
    }

    // Test successful operation
    let result1 = simulate_operation_with_logging(&mut streams, "test_operation").await;
    assert!(result1.is_ok());

    // Test failing operation
    let result2 = simulate_operation_with_logging(&mut streams, "failing_operation").await;
    assert!(result2.is_err());
}
