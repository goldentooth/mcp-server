use goldentooth_mcp::protocol::process_json_request;
use goldentooth_mcp::types::McpStreams;
use serde_json::{Value, json};
use std::io::Cursor;

/// Helper function to process an MCP request directly (fast, no subprocess)
async fn process_mcp_request_direct(request: Value) -> Value {
    // Create test streams that capture output to memory buffers
    let stdout_buf = Vec::new();
    let stderr_buf = Vec::new();

    let mut streams =
        McpStreams::new_with_writers(Cursor::new(stdout_buf), Cursor::new(stderr_buf));

    // Process the request directly using our protocol module
    let request_str = request.to_string();
    let response = process_json_request(&request_str, &mut streams)
        .await
        .expect("Failed to process JSON request");

    // Convert the response to JSON value for easy assertions
    let response_json = response
        .to_json_string()
        .expect("Failed to serialize response");
    serde_json::from_str(&response_json).expect("Failed to parse response JSON")
}

#[tokio::test]
async fn test_cluster_ping_all_nodes() {
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 1,
        "params": {
            "name": "cluster_ping",
            "arguments": {}
        }
    });

    let response = process_mcp_request_direct(request).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 1);
    assert!(response["result"].is_object());

    let result = &response["result"];
    assert!(result["nodes"].is_object());
    assert!(result["summary"].is_object());

    let summary = &result["summary"];
    assert!(summary["total_nodes"].as_u64().unwrap() > 0);
    assert!(summary["reachable_nodes"].as_u64().is_some());
    assert!(summary["unreachable_nodes"].as_u64().is_some());
}

#[tokio::test]
async fn test_cluster_status_all_nodes() {
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 2,
        "params": {
            "name": "cluster_status",
            "arguments": {}
        }
    });

    let response = process_mcp_request_direct(request).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 2);
    assert!(response["result"].is_object());

    let result = &response["result"];
    assert!(result["nodes"].is_object());
    assert!(result["queried_at"].is_string());

    // Check that we have node status information
    let nodes = result["nodes"].as_object().unwrap();
    if !nodes.is_empty() {
        let (_, node_status) = nodes.iter().next().unwrap();
        if node_status["status"].as_str() != Some("error") {
            assert!(node_status["hostname"].is_string());
            assert!(node_status["uptime_seconds"].is_number());
            assert!(node_status["load_average"].is_array());
        }
    }
}

#[tokio::test]
async fn test_cluster_status_specific_node() {
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 3,
        "params": {
            "name": "cluster_status",
            "arguments": {
                "node": "allyrion"
            }
        }
    });

    let response = process_mcp_request_direct(request).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 3);
    assert!(response["result"].is_object());

    let result = &response["result"];
    let nodes = result["nodes"].as_object().unwrap();

    // Should only have one node (allyrion)
    assert_eq!(nodes.len(), 1);
    assert!(nodes.contains_key("allyrion"));
}

#[tokio::test]
async fn test_service_status_consul() {
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 4,
        "params": {
            "name": "service_status",
            "arguments": {
                "service": "consul"
            }
        }
    });

    let response = process_mcp_request_direct(request).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 4);
    assert!(response["result"].is_object());

    let result = &response["result"];
    assert_eq!(result["service"], "consul");
    assert!(result["nodes"].is_object());
    assert!(result["queried_at"].is_string());

    // Check service status structure if we have results
    let nodes = result["nodes"].as_object().unwrap();
    if !nodes.is_empty() {
        let (_, service_status) = nodes.iter().next().unwrap();
        if service_status["status"].as_str() != Some("error") {
            assert!(service_status["service"].is_string());
            assert!(service_status["status"].is_string());
            assert!(service_status["enabled"].is_boolean());
            assert!(service_status["running"].is_boolean());
        }
    }
}

#[tokio::test]
async fn test_service_status_specific_node() {
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 5,
        "params": {
            "name": "service_status",
            "arguments": {
                "service": "ssh",
                "node": "allyrion"
            }
        }
    });

    let response = process_mcp_request_direct(request).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 5);
    assert!(response["result"].is_object());

    let result = &response["result"];
    assert_eq!(result["service"], "ssh");

    let nodes = result["nodes"].as_object().unwrap();
    // Should only have one node (allyrion)
    assert_eq!(nodes.len(), 1);
    assert!(nodes.contains_key("allyrion"));
}

#[tokio::test]
async fn test_resource_usage_all_nodes() {
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 6,
        "params": {
            "name": "resource_usage",
            "arguments": {}
        }
    });

    let response = process_mcp_request_direct(request).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 6);
    assert!(response["result"].is_object());

    let result = &response["result"];
    assert!(result["nodes"].is_object());
    assert!(result["queried_at"].is_string());

    // Check resource usage structure if we have results
    let nodes = result["nodes"].as_object().unwrap();
    if !nodes.is_empty() {
        let (_, resource_info) = nodes.iter().next().unwrap();
        if resource_info["status"].as_str() != Some("error") {
            assert!(resource_info["hostname"].is_string());
            assert!(resource_info["memory"].is_object());
            assert!(resource_info["disk"].is_object());
            assert!(resource_info["cpu"].is_object());

            let memory = &resource_info["memory"];
            assert!(memory["used_mb"].is_number());
            assert!(memory["total_mb"].is_number());
            assert!(memory["percentage"].is_number());
            assert!(memory["free_mb"].is_number());

            let disk = &resource_info["disk"];
            assert!(disk["used_gb"].is_number());
            assert!(disk["total_gb"].is_number());
            assert!(disk["percentage"].is_number());
            assert!(disk["free_gb"].is_number());
        }
    }
}

#[tokio::test]
async fn test_resource_usage_specific_node() {
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 7,
        "params": {
            "name": "resource_usage",
            "arguments": {
                "node": "velaryon"
            }
        }
    });

    let response = process_mcp_request_direct(request).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 7);
    assert!(response["result"].is_object());

    let result = &response["result"];
    let nodes = result["nodes"].as_object().unwrap();

    // Should only have one node (velaryon)
    assert_eq!(nodes.len(), 1);
    assert!(nodes.contains_key("velaryon"));
}

#[tokio::test]
async fn test_shell_command_basic() {
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 8,
        "params": {
            "name": "shell_command",
            "arguments": {
                "command": "hostname"
            }
        }
    });

    let response = process_mcp_request_direct(request).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 8);
    assert!(response["result"].is_object());

    let result = &response["result"];
    assert_eq!(result["command"], "hostname");
    assert_eq!(result["node"], "allyrion"); // default node
    assert!(result["exit_code"].is_number());
    assert!(result["stdout"].is_string());
    assert!(result["stderr"].is_string());
    assert!(result["success"].is_boolean());
    assert!(result["duration_seconds"].is_number());
    assert!(result["executed_at"].is_string());
}

#[tokio::test]
async fn test_shell_command_with_node() {
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 9,
        "params": {
            "name": "shell_command",
            "arguments": {
                "command": "uptime",
                "node": "jast"
            }
        }
    });

    let response = process_mcp_request_direct(request).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 9);
    assert!(response["result"].is_object());

    let result = &response["result"];
    assert_eq!(result["command"], "uptime");
    assert_eq!(result["node"], "jast");
}

#[tokio::test]
async fn test_shell_command_dangerous_blocked() {
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 10,
        "params": {
            "name": "shell_command",
            "arguments": {
                "command": "rm -rf /"
            }
        }
    });

    let response = process_mcp_request_direct(request).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 10);

    // Should have an error field due to dangerous command validation
    assert!(response["error"].is_object());
    assert_eq!(response["error"]["code"], -32602); // Invalid params
}

#[tokio::test]
async fn test_invalid_node_name() {
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 11,
        "params": {
            "name": "cluster_status",
            "arguments": {
                "node": "invalid_node"
            }
        }
    });

    let response = process_mcp_request_direct(request).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 11);

    // Should have an error field due to invalid node name
    assert!(response["error"].is_object());
    assert_eq!(response["error"]["code"], -32602); // Invalid params
}

#[tokio::test]
async fn test_missing_required_service_parameter() {
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 12,
        "params": {
            "name": "service_status",
            "arguments": {}
        }
    });

    let response = process_mcp_request_direct(request).await;

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 12);

    // Should have an error field due to missing service parameter
    assert!(response["error"].is_object());
    assert_eq!(response["error"]["code"], -32602); // Invalid params
}

#[tokio::test]
async fn test_concurrent_tool_calls() {
    use futures::future::join_all;

    // Create multiple concurrent requests to test race conditions
    let requests = vec![
        json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 100,
            "params": {
                "name": "cluster_ping",
                "arguments": {}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 101,
            "params": {
                "name": "resource_usage",
                "arguments": {"node": "allyrion"}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 102,
            "params": {
                "name": "service_status",
                "arguments": {"service": "ssh", "node": "jast"}
            }
        }),
    ];

    let futures = requests
        .into_iter()
        .map(process_mcp_request_direct);
    let responses = join_all(futures).await;

    // All requests should complete successfully
    assert_eq!(responses.len(), 3);

    for (i, response) in responses.iter().enumerate() {
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 100 + i);
        // Should either have a result or an error, but not both
        assert!(response["result"].is_object() ^ response["error"].is_object());
    }
}
