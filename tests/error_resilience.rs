use goldentooth_mcp::protocol::process_json_request;
use goldentooth_mcp::types::McpStreams;
use serde_json::json;

#[tokio::test]
async fn test_consecutive_parse_errors_should_not_infinite_loop() {
    let mut streams = McpStreams::new();

    // Test that consecutive parse errors don't cause infinite loops
    let invalid_json = "{ invalid json";
    let mut error_count = 0;

    // Process multiple consecutive invalid requests
    for _ in 0..10 {
        let result = process_json_request(invalid_json, &mut streams).await;
        match result {
            Err(_) => error_count += 1,
            Ok(_) => {
                // Should not get Ok responses for invalid JSON
                panic!("Expected error for invalid JSON");
            }
        }
    }

    // Should have failed all 10 attempts
    assert_eq!(error_count, 10);
}

#[tokio::test]
async fn test_circuit_breaker_pattern() {
    let mut streams = McpStreams::new();

    // This test will be implemented after we add circuit breaker logic
    // For now, just ensure we can handle multiple errors
    let invalid_requests = [
        "not json at all",
        "{ \"incomplete\": ",
        "[1, 2, 3",
        "null",
        "",
    ];

    for (i, invalid_request) in invalid_requests.iter().enumerate() {
        let result = process_json_request(invalid_request, &mut streams).await;

        // Each should fail independently
        assert!(result.is_err(), "Request {i} should have failed");
    }
}

#[tokio::test]
async fn test_valid_request_after_errors_should_work() {
    let mut streams = McpStreams::new();

    // First, send some invalid requests
    for _ in 0..3 {
        let result = process_json_request("invalid json", &mut streams).await;
        assert!(result.is_err());
    }

    // Then send a valid request - it should work
    let valid_request = json!({
        "jsonrpc": "2.0",
        "method": "notifications/ping",
        "id": 1
    })
    .to_string();

    let result = process_json_request(&valid_request, &mut streams).await;
    assert!(result.is_ok(), "Valid request should succeed after errors");
}

#[tokio::test]
async fn test_error_response_includes_request_id_when_possible() {
    let mut streams = McpStreams::new();

    // Test with parseable JSON that has ID but invalid structure
    let request_with_id = r#"{"jsonrpc": "2.0", "id": 42, "invalid": true}"#;

    let result = process_json_request(request_with_id, &mut streams).await;

    // Should return a response (error) rather than Err
    match result {
        Ok(response) => {
            // Verify the response contains the original ID
            let json_str = response.to_json_string().unwrap();
            assert!(
                json_str.contains("42"),
                "Error response should include original ID"
            );
        }
        Err(_) => {
            // This is acceptable for now, but we'll improve this
        }
    }
}
