//! Type-safe tool execution tests
//!
//! These tests demonstrate the type-safe tool execution system and show
//! how compile-time safety prevents common errors in tool usage.

use goldentooth_mcp::tools::*;
use goldentooth_mcp::types::*;
use serde_json::json;

#[tokio::test]
async fn test_type_safe_cluster_ping() {
    // Type-safe cluster ping execution
    let args = ClusterPingArgs::default();
    let tool_args = ToolArgs::ClusterPing(args);

    let result = execute_tool_type_safe(tool_args).await;
    assert!(result.is_ok());

    let response = result.unwrap();
    assert!(response["nodes"].is_object());
    assert!(response["summary"].is_object());

    let nodes = response["nodes"].as_object().unwrap();
    assert!(!nodes.is_empty());

    // Check that all valid nodes are included
    for valid_node in NodeName::valid_nodes() {
        assert!(nodes.contains_key(*valid_node));
        let node_info = &nodes[*valid_node];
        // Status can be "reachable", "unreachable", or "error" depending on real cluster state
        assert!(
            ["reachable", "unreachable", "error"].contains(&node_info["status"].as_str().unwrap())
        );
        assert!(node_info["ping_time_ms"].is_number());
    }
}

#[tokio::test]
async fn test_type_safe_cluster_status() {
    // Test with no specific node (all nodes)
    let args = ClusterStatusArgs { node: None };
    let tool_args = ToolArgs::ClusterStatus(args);

    let result = execute_tool_type_safe(tool_args).await;
    assert!(result.is_ok());

    let response = result.unwrap();
    assert!(response["nodes"].is_object());
    assert!(response["queried_at"].is_string());

    let nodes = response["nodes"].as_object().unwrap();
    assert_eq!(nodes.len(), NodeName::valid_nodes().len());

    // Test with specific node
    let node = NodeName::new("allyrion").unwrap();
    let args = ClusterStatusArgs { node: Some(node) };
    let tool_args = ToolArgs::ClusterStatus(args);

    let result = execute_tool_type_safe(tool_args).await;
    assert!(result.is_ok());

    let response = result.unwrap();
    let nodes = response["nodes"].as_object().unwrap();
    assert_eq!(nodes.len(), 1);
    assert!(nodes.contains_key("allyrion"));

    let node_info = &nodes["allyrion"];
    assert_eq!(node_info["hostname"], "allyrion");
    assert!(node_info["uptime_seconds"].is_number());
    assert!(node_info["memory_usage"].is_object());
    assert!(node_info["cpu_usage"].is_object());
}

#[tokio::test]
async fn test_type_safe_service_status() {
    // Test service status with type-safe arguments
    let service = ServiceName::new("consul").unwrap();
    let node = NodeName::new("jast").unwrap();
    let args = ServiceStatusArgs {
        service,
        node: Some(node),
    };
    let tool_args = ToolArgs::ServiceStatus(args);

    let result = execute_tool_type_safe(tool_args).await;
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response["service"], "consul");
    assert!(response["nodes"].is_object());

    let nodes = response["nodes"].as_object().unwrap();
    assert_eq!(nodes.len(), 1);
    assert!(nodes.contains_key("jast"));

    let service_info = &nodes["jast"];
    assert_eq!(service_info["service"], "consul");
    // Service status depends on real cluster state - could be active, inactive, or error
    assert!(service_info["status"].is_string());
    assert!(service_info["enabled"].is_boolean());
    assert!(service_info["running"].is_boolean());
}

#[tokio::test]
async fn test_type_safe_shell_command() {
    // Test safe shell command
    let command = ShellCommand::new("echo 'Hello, World!'").unwrap();
    let node = NodeName::new("allyrion").unwrap();
    let args = ShellCommandArgs {
        command,
        node: Some(node),
        as_root: Some(false),
        timeout: Some(10),
    };
    let tool_args = ToolArgs::ShellCommand(args);

    let result = execute_tool_type_safe(tool_args).await;
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response["command"], "echo 'Hello, World!'");
    assert_eq!(response["node"], "allyrion");
    assert_eq!(response["as_root"], false);
    assert_eq!(response["timeout"], 10);
    // Exit code depends on real SSH execution - could be 0 for success or non-zero for failure
    assert!(response["exit_code"].is_number());
    assert!(response["stdout"].is_string());
    assert!(response["executed_at"].is_string());
}

#[test]
fn test_type_safe_argument_parsing() {
    // Test parsing valid JSON to type-safe arguments
    let params = json!({"node": "allyrion"});
    let result = parse_tool_arguments("cluster_status", params);
    assert!(result.is_ok());

    if let Ok(ToolArgs::ClusterStatus(args)) = result {
        assert!(args.node.is_some());
        assert_eq!(args.node.unwrap().as_str(), "allyrion");
    } else {
        panic!("Expected ClusterStatus arguments");
    }

    // Test parsing service status arguments
    let params = json!({"service": "consul", "node": "jast"});
    let result = parse_tool_arguments("service_status", params);
    assert!(result.is_ok());

    if let Ok(ToolArgs::ServiceStatus(args)) = result {
        assert_eq!(args.service.as_str(), "consul");
        assert!(args.node.is_some());
        assert_eq!(args.node.unwrap().as_str(), "jast");
    } else {
        panic!("Expected ServiceStatus arguments");
    }
}

#[test]
fn test_argument_parsing_validation() {
    // Test parsing with invalid node name
    let params = json!({"node": "invalid_node"});
    let result = parse_tool_arguments("cluster_status", params);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Unknown node"));

    // Test parsing with missing required parameter
    let params = json!({});
    let result = parse_tool_arguments("service_status", params);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .contains("Missing required parameter: service")
    );

    // Test parsing with invalid service name
    let params = json!({"service": ""});
    let result = parse_tool_arguments("service_status", params);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("empty"));

    // Test parsing dangerous shell command
    let params = json!({"command": "rm -rf /"});
    let result = parse_tool_arguments("shell_command", params);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("dangerous"));
}

#[test]
fn test_compile_time_safety_prevents_errors() {
    // These would be compile errors if uncommented:

    // Can't create invalid node names
    // let invalid_node = NodeName("invalid".to_string()); // Private constructor

    // Can't create dangerous commands directly
    // let dangerous_cmd = ShellCommand("rm -rf /".to_string()); // Private constructor

    // Invalid arguments at construction time
    assert!(NodeName::new("invalid_node").is_err());
    assert!(ServiceName::new("").is_err());
    assert!(ShellCommand::new("rm -rf /").is_err());
    assert!(HttpUrl::new("not-a-url").is_err());
    assert!(LogQLQuery::new("invalid").is_err());

    // Tool names are compile-time constants
    assert_eq!(ClusterPingArgs::TOOL_NAME, "cluster_ping");
    assert_eq!(ServiceStatusArgs::TOOL_NAME, "service_status");
    assert_eq!(ShellCommandArgs::TOOL_NAME, "shell_command");
}

#[test]
fn test_tool_argument_validation() {
    // All tool argument types validate correctly
    let cluster_ping = ClusterPingArgs::default();
    assert!(cluster_ping.validate().is_ok());

    let cluster_status = ClusterStatusArgs {
        node: Some(NodeName::new("allyrion").unwrap()),
    };
    assert!(cluster_status.validate().is_ok());

    let service_status = ServiceStatusArgs {
        service: ServiceName::new("consul").unwrap(),
        node: Some(NodeName::new("jast").unwrap()),
    };
    assert!(service_status.validate().is_ok());

    // Shell command validation includes security checks
    let safe_shell = ShellCommandArgs {
        command: ShellCommand::new("ls -la").unwrap(),
        node: None,
        as_root: None,
        timeout: None,
    };
    assert!(safe_shell.validate().is_ok());

    // Invalid journald args (follow mode not allowed)
    let invalid_journald = JournaldLogsArgs {
        node: None,
        service: None,
        priority: None,
        since: None,
        lines: None,
        follow: Some(true), // Not allowed in MCP context
    };
    assert!(invalid_journald.validate().is_err());
}

#[tokio::test]
async fn test_error_propagation() {
    // Test that type-safe errors are properly propagated

    // This would fail if we tried to create an invalid tool argument:
    // But since we have type safety, we can't create invalid arguments

    // Test unimplemented tool handling - ClusterInfo is defined but not implemented yet
    let unimplemented_tool = ToolArgs::ClusterInfo(ClusterInfoArgs::default());
    let result = execute_tool_type_safe(unimplemented_tool).await;
    assert!(result.is_err());

    // Check that the error is properly structured
    let error = result.unwrap_err();
    assert_eq!(error.error_info().code, 1001); // Tool not found error code
    assert!(error.error_info().message.contains("not found"));
}
