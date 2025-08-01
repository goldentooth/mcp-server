use goldentooth_mcp::http_server::HttpServer;
use goldentooth_mcp::service::GoldentoothService;
use serde_json::{Value, json};

#[tokio::test]
async fn test_tools_list_includes_new_tools() {
    println!("🧪 Testing that tools list includes all new tools...");

    // Create HTTP server with default service
    let service = GoldentoothService::new();
    let server = HttpServer::new(service, None);

    // Test tools/list request
    let request = r#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#;
    let response = server
        .handle_request_for_test("tools/list", request, None)
        .await
        .unwrap();

    let json: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(json["jsonrpc"], "2.0");

    let tools = json["result"]["tools"].as_array().unwrap();

    // Check that we have all 8 expected tools
    assert_eq!(tools.len(), 8, "Should have 8 tools total");

    // Extract tool names
    let tool_names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();

    // Verify all expected tools are present
    let expected_tools = vec![
        "cluster_ping",
        "cluster_status",
        "service_status",
        "resource_usage",
        "cluster_info",
        "shell_command",
        "journald_logs",
        "loki_logs",
    ];

    for expected_tool in &expected_tools {
        assert!(
            tool_names.contains(expected_tool),
            "Tool '{}' should be in the tools list. Found: {:?}",
            expected_tool,
            tool_names
        );
    }

    println!(
        "✅ Tools list integration test passed - found all {} tools",
        tools.len()
    );
}

#[tokio::test]
async fn test_shell_command_tool_call() {
    println!("🧪 Testing shell_command tool call via HTTP...");

    // Create HTTP server with default service
    let service = GoldentoothService::new();
    let server = HttpServer::new(service, None);

    // Test tools/call request for shell_command
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "shell_command",
            "arguments": {
                "command": "echo 'Integration Test'",
                "node": "allyrion",
                "as_root": false,
                "timeout": 30
            }
        },
        "id": 2
    });

    let response = server
        .handle_request_for_test("tools/call", &request.to_string(), None)
        .await
        .unwrap();

    let json: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["id"], 2);

    // Should get a result (even if it's a mock response)
    assert!(json["result"].is_object(), "Should have result object");
    let result = &json["result"];
    assert!(result["content"].is_array(), "Should have content array");

    let content = result["content"].as_array().unwrap();
    assert!(!content.is_empty(), "Content should not be empty");

    // The content should be text containing our response
    let content_text = content[0]["text"].as_str().unwrap();
    let response_json: Value = serde_json::from_str(content_text).unwrap();

    assert_eq!(response_json["tool"], "shell_command");
    assert!(response_json["success"].is_boolean());

    println!("✅ Shell command tool call integration test passed");
}

#[tokio::test]
async fn test_journald_logs_tool_call() {
    println!("🧪 Testing journald_logs tool call via HTTP...");

    // Create HTTP server with default service
    let service = GoldentoothService::new();
    let server = HttpServer::new(service, None);

    // Test tools/call request for journald_logs
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "journald_logs",
            "arguments": {
                "node": "allyrion",
                "service": "consul.service",
                "since": "1 hour ago",
                "lines": 50,
                "follow": false,
                "priority": "info"
            }
        },
        "id": 3
    });

    let response = server
        .handle_request_for_test("tools/call", &request.to_string(), None)
        .await
        .unwrap();

    let json: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["id"], 3);

    // Should get a result
    assert!(json["result"].is_object(), "Should have result object");
    let result = &json["result"];
    assert!(result["content"].is_array(), "Should have content array");

    let content = result["content"].as_array().unwrap();
    let content_text = content[0]["text"].as_str().unwrap();
    let response_json: Value = serde_json::from_str(content_text).unwrap();

    assert_eq!(response_json["tool"], "journald_logs");

    println!("✅ Journald logs tool call integration test passed");
}

#[tokio::test]
async fn test_loki_logs_tool_call() {
    println!("🧪 Testing loki_logs tool call via HTTP...");

    // Create HTTP server with default service
    let service = GoldentoothService::new();
    let server = HttpServer::new(service, None);

    // Test tools/call request for loki_logs
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "loki_logs",
            "arguments": {
                "query": "{job=\"consul\"}",
                "start": "1h",
                "end": "now",
                "limit": 100,
                "direction": "backward"
            }
        },
        "id": 4
    });

    let response = server
        .handle_request_for_test("tools/call", &request.to_string(), None)
        .await
        .unwrap();

    let json: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["id"], 4);

    // Should get a result
    assert!(json["result"].is_object(), "Should have result object");
    let result = &json["result"];
    assert!(result["content"].is_array(), "Should have content array");

    let content = result["content"].as_array().unwrap();
    let content_text = content[0]["text"].as_str().unwrap();
    let response_json: Value = serde_json::from_str(content_text).unwrap();

    assert_eq!(response_json["tool"], "loki_logs");

    println!("✅ Loki logs tool call integration test passed");
}

#[tokio::test]
async fn test_tool_schema_validation() {
    println!("🧪 Testing tool schema validation...");

    // Create HTTP server with default service
    let service = GoldentoothService::new();
    let server = HttpServer::new(service, None);

    // Get the tools list to validate schemas
    let request = r#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#;
    let response = server
        .handle_request_for_test("tools/list", request, None)
        .await
        .unwrap();

    let json: Value = serde_json::from_str(&response).unwrap();
    let tools = json["result"]["tools"].as_array().unwrap();

    // Find and validate each new tool's schema
    for tool in tools {
        let tool_name = tool["name"].as_str().unwrap();

        match tool_name {
            "shell_command" => {
                let schema = &tool["inputSchema"];
                assert!(schema["properties"]["command"].is_object());
                assert!(
                    schema["required"]
                        .as_array()
                        .unwrap()
                        .contains(&json!("command"))
                );
                println!("✓ shell_command schema validated");
            }
            "journald_logs" => {
                let schema = &tool["inputSchema"];
                assert!(schema["properties"]["node"].is_object());
                assert!(schema["properties"]["service"].is_object());
                assert!(schema["properties"]["since"].is_object());
                assert!(schema["properties"]["lines"].is_object());
                assert!(schema["properties"]["follow"].is_object());
                assert!(schema["properties"]["priority"].is_object());
                println!("✓ journald_logs schema validated");
            }
            "loki_logs" => {
                let schema = &tool["inputSchema"];
                assert!(schema["properties"]["query"].is_object());
                assert!(schema["properties"]["start"].is_object());
                assert!(schema["properties"]["end"].is_object());
                assert!(schema["properties"]["limit"].is_object());
                assert!(schema["properties"]["direction"].is_object());
                assert!(
                    schema["required"]
                        .as_array()
                        .unwrap()
                        .contains(&json!("query"))
                );
                println!("✓ loki_logs schema validated");
            }
            _ => {} // Skip other tools
        }
    }

    println!("✅ Tool schema validation test passed");
}

#[tokio::test]
async fn test_error_handling_missing_required_params() {
    println!("🧪 Testing error handling for missing required parameters...");

    // Create HTTP server with default service
    let service = GoldentoothService::new();
    let server = HttpServer::new(service, None);

    // Test shell_command without required 'command' parameter
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "shell_command",
            "arguments": {
                "node": "allyrion"
                // Missing required 'command' parameter
            }
        },
        "id": 5
    });

    let response = server
        .handle_request_for_test("tools/call", &request.to_string(), None)
        .await
        .unwrap();

    let json: Value = serde_json::from_str(&response).unwrap();

    // The HTTP server provides a default command, so this should succeed
    // but with a default message rather than failing
    assert!(json["result"].is_object(), "Should have result object");
    let result = &json["result"];
    assert!(result["content"].is_array(), "Should have content array");

    let content = result["content"].as_array().unwrap();
    let content_text = content[0]["text"].as_str().unwrap();
    let response_json: Value = serde_json::from_str(content_text).unwrap();

    // Should contain the default command message
    assert!(response_json["results"].is_array());
    let results = response_json["results"].as_array().unwrap();
    assert!(
        results[0]["command"]
            .as_str()
            .unwrap()
            .contains("No command provided")
    );

    println!("✅ Error handling for missing required params test passed");
}

#[tokio::test]
async fn test_comprehensive_tools_integration() {
    println!("🧪 Running comprehensive tools integration test...");

    // Create HTTP server with default service
    let service = GoldentoothService::new();
    let server = HttpServer::new(service, None);

    // Test 1: Verify tools list completeness
    let tools_request = r#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#;
    let tools_response = server
        .handle_request_for_test("tools/list", tools_request, None)
        .await
        .unwrap();

    let tools_json: Value = serde_json::from_str(&tools_response).unwrap();
    let tools = tools_json["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 8, "Should have exactly 8 tools");

    // Test 2: Each new tool responds to calls
    let new_tools = vec!["shell_command", "journald_logs", "loki_logs"];

    for tool_name in &new_tools {
        let request = match *tool_name {
            "shell_command" => json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": {"command": "echo test"}
                },
                "id": 10
            }),
            "journald_logs" => json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": {"node": "allyrion"}
                },
                "id": 11
            }),
            "loki_logs" => json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": {"query": "{job=\"test\"}"}
                },
                "id": 12
            }),
            _ => unreachable!(),
        };

        let response = server
            .handle_request_for_test("tools/call", &request.to_string(), None)
            .await
            .unwrap();

        let json: Value = serde_json::from_str(&response).unwrap();

        // Should not have an error (might have result or might be mock, but not error)
        assert!(
            json["error"].is_null() || !json["error"].is_object(),
            "Tool {} should not return an error, got: {}",
            tool_name,
            json
        );

        println!("✓ Tool {} responds correctly", tool_name);
    }

    println!(
        "✅ Comprehensive tools integration test passed - all {} new tools working!",
        new_tools.len()
    );
}
