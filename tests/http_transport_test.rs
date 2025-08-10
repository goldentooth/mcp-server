use goldentooth_mcp::transport::HttpTransport;
use serde_json::json;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_http_transport_cluster_ping() {
    // Set environment to disable auth for testing
    unsafe {
        std::env::set_var("MCP_AUTH_REQUIRED", "false");
    }

    // Create HTTP transport
    let transport = HttpTransport::new(false);
    let addr = transport
        .start()
        .await
        .expect("Should start HTTP transport successfully");

    // Give server time to start
    sleep(Duration::from_millis(100)).await;

    // Create HTTP client
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/mcp");

    // Test cluster_ping via HTTP POST
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 1,
        "params": {
            "name": "cluster_ping",
            "arguments": {}
        }
    });

    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&request_body)
        .timeout(Duration::from_secs(30)) // Allow time for real cluster operations
        .send()
        .await
        .expect("HTTP request should succeed");

    assert!(
        response.status().is_success(),
        "HTTP status should be 200 OK"
    );

    let response_json: serde_json::Value = response
        .json()
        .await
        .expect("Response should be valid JSON");

    // Verify JSON-RPC response structure
    assert_eq!(response_json["jsonrpc"], "2.0");
    assert_eq!(response_json["id"], 1);
    assert!(response_json["result"].is_object());

    let result = &response_json["result"];
    assert!(result["nodes"].is_object());
    assert!(result["summary"].is_object());

    // Verify we get meaningful cluster ping results
    let summary = &result["summary"];
    assert!(summary["total_nodes"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn test_http_transport_sse_mode() {
    unsafe {
        std::env::set_var("MCP_AUTH_REQUIRED", "false");
    }

    let transport = HttpTransport::new(false);
    let addr = transport
        .start()
        .await
        .expect("Should start HTTP transport successfully");

    sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/mcp");

    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 2,
        "params": {
            "name": "cluster_ping",
            "arguments": {}
        }
    });

    // Request SSE response format
    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Accept", "text/event-stream")
        .json(&request_body)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .expect("HTTP SSE request should succeed");

    assert!(response.status().is_success());
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/event-stream"
    );

    let body = response.text().await.expect("Should get response body");
    assert!(body.starts_with("data: "));
    assert!(body.contains("jsonrpc"));
    assert!(body.contains("\"id\":2"));
}

#[tokio::test]
async fn test_http_transport_invalid_endpoint() {
    unsafe {
        std::env::set_var("MCP_AUTH_REQUIRED", "false");
    }

    let transport = HttpTransport::new(false);
    let addr = transport
        .start()
        .await
        .expect("Should start HTTP transport successfully");

    sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/invalid");

    let response = client
        .post(&url)
        .json(&json!({}))
        .send()
        .await
        .expect("HTTP request should complete");

    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_http_transport_with_auth_required() {
    // Test that authentication is enforced when required
    let transport = HttpTransport::new(true); // auth required
    let addr = transport
        .start()
        .await
        .expect("Should start HTTP transport successfully");

    sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/mcp");

    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 3,
        "params": {
            "name": "cluster_ping",
            "arguments": {}
        }
    });

    // Request without auth header should fail
    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await
        .expect("HTTP request should complete");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

    let error_json: serde_json::Value = response
        .json()
        .await
        .expect("Error response should be valid JSON");

    assert_eq!(error_json["error"]["code"], -32001);
    assert!(
        error_json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Authentication required")
    );
}
