use async_trait::async_trait;
use serde_json::{Value, json};
use std::collections::HashMap;

use crate::types::*;

/// Type-safe MCP tool trait
///
/// This trait provides compile-time guarantees for tool argument validation
/// by using strongly-typed parameters instead of raw JSON Values.
#[async_trait]
pub trait TypeSafeMcpTool<Args>: Send + Sync
where
    Args: ToolArguments + Send + Sync,
{
    /// Get the tool name (must match Args::TOOL_NAME)
    fn name(&self) -> &'static str {
        Args::TOOL_NAME
    }

    /// Get tool description for clients
    fn description(&self) -> &str;

    /// Get JSON schema for tool arguments
    fn input_schema(&self) -> Value;

    /// Execute the tool with type-safe arguments
    async fn execute(&self, args: Args) -> ToolResult<Value>;
}

/// Type-safe cluster ping tool implementation
pub struct ClusterPingTool;

#[async_trait]
impl TypeSafeMcpTool<ClusterPingArgs> for ClusterPingTool {
    fn description(&self) -> &str {
        "Ping all nodes in the Goldentooth cluster to check connectivity"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false,
            "description": "No arguments required - pings all cluster nodes"
        })
    }

    async fn execute(&self, _args: ClusterPingArgs) -> ToolResult<Value> {
        // Minimal implementation that returns mock results
        let mut nodes = HashMap::new();

        // Mock ping results for all known nodes
        for node in NodeName::valid_nodes() {
            nodes.insert(
                *node,
                json!({
                    "status": "reachable",
                    "ping_time_ms": 1.2,
                    "icmp_reachable": true,
                    "tcp_port_22_open": true
                }),
            );
        }

        Ok(json!({
            "nodes": nodes,
            "summary": {
                "total_nodes": nodes.len(),
                "reachable_nodes": nodes.len(),
                "unreachable_nodes": 0
            }
        }))
    }
}

/// Type-safe cluster status tool implementation
pub struct ClusterStatusTool;

#[async_trait]
impl TypeSafeMcpTool<ClusterStatusArgs> for ClusterStatusTool {
    fn description(&self) -> &str {
        "Get detailed status information for cluster nodes"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "node": {
                    "type": "string",
                    "description": "Specific node to check (optional, defaults to all nodes)",
                    "enum": NodeName::valid_nodes()
                }
            },
            "additionalProperties": false
        })
    }

    async fn execute(&self, args: ClusterStatusArgs) -> ToolResult<Value> {
        let nodes_to_check: Vec<&str> = match &args.node {
            Some(node) => vec![node.as_str()],
            None => NodeName::valid_nodes().to_vec(),
        };

        let mut node_statuses = HashMap::new();

        for node in nodes_to_check {
            node_statuses.insert(
                node,
                json!({
                    "hostname": node,
                    "uptime_seconds": 86400,
                    "load_average": [0.5, 0.3, 0.2],
                    "memory_usage": {
                        "used_mb": 512,
                        "total_mb": 2048,
                        "percentage": 25.0
                    },
                    "cpu_usage": {
                        "percentage": 15.0,
                        "temperature_c": 45.5
                    },
                    "disk_usage": {
                        "used_gb": 8,
                        "total_gb": 32,
                        "percentage": 25.0
                    },
                    "network": {
                        "interface": "eth0",
                        "ip_address": format!("10.4.0.{}", (node.len() * 10) % 254)
                    },
                    "status": "healthy"
                }),
            );
        }

        Ok(json!({
            "nodes": node_statuses,
            "queried_at": chrono::Utc::now().to_rfc3339()
        }))
    }
}

/// Type-safe service status tool implementation
pub struct ServiceStatusTool;

#[async_trait]
impl TypeSafeMcpTool<ServiceStatusArgs> for ServiceStatusTool {
    fn description(&self) -> &str {
        "Check the status of systemd services on cluster nodes"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Service name to check (e.g., 'consul', 'nomad', 'vault')"
                },
                "node": {
                    "type": "string",
                    "description": "Specific node to check (optional, defaults to all nodes)",
                    "enum": NodeName::valid_nodes()
                }
            },
            "required": ["service"],
            "additionalProperties": false
        })
    }

    async fn execute(&self, args: ServiceStatusArgs) -> ToolResult<Value> {
        let nodes_to_check: Vec<&str> = match &args.node {
            Some(node) => vec![node.as_str()],
            None => NodeName::valid_nodes().to_vec(),
        };

        let mut node_statuses = HashMap::new();

        for node in nodes_to_check {
            node_statuses.insert(
                node,
                json!({
                    "service": args.service.as_str(),
                    "status": "active",
                    "enabled": true,
                    "running": true,
                    "pid": 12345,
                    "memory_usage_mb": 64,
                    "cpu_usage_percent": 2.5,
                    "uptime_seconds": 3600,
                    "last_restart": "2024-01-01T12:00:00Z",
                    "restart_count": 0
                }),
            );
        }

        Ok(json!({
            "service": args.service.as_str(),
            "nodes": node_statuses,
            "queried_at": chrono::Utc::now().to_rfc3339()
        }))
    }
}

/// Type-safe shell command tool implementation
pub struct ShellCommandTool;

#[async_trait]
impl TypeSafeMcpTool<ShellCommandArgs> for ShellCommandTool {
    fn description(&self) -> &str {
        "Execute arbitrary shell commands on cluster nodes via SSH"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command to execute (security validated)"
                },
                "node": {
                    "type": "string",
                    "description": "Specific node to run on (optional, defaults to allyrion)",
                    "enum": NodeName::valid_nodes()
                },
                "as_root": {
                    "type": "boolean",
                    "description": "Whether to execute as root user"
                },
                "timeout": {
                    "type": "integer",
                    "description": "Command timeout in seconds",
                    "minimum": 1,
                    "maximum": 300
                }
            },
            "required": ["command"],
            "additionalProperties": false
        })
    }

    async fn execute(&self, args: ShellCommandArgs) -> ToolResult<Value> {
        // Validate command safety at execution time as well
        args.validate().map_err(|e| {
            TypeSafeError::<error_contexts::Argument>::from_tool_argument_error(
                e,
                MessageId::Number(0),
            )
            .map_context::<error_contexts::Tool>()
        })?;

        let target_node = args.node.as_ref().map(|n| n.as_str()).unwrap_or("allyrion");

        let timeout = args.timeout.unwrap_or(30);
        let as_root = args.as_root.unwrap_or(false);

        // Mock command execution
        let mock_output = format!(
            "Mock execution of '{}' on node '{}'",
            args.command.as_str(),
            target_node
        );

        Ok(json!({
            "command": args.command.as_str(),
            "node": target_node,
            "as_root": as_root,
            "timeout": timeout,
            "exit_code": 0,
            "stdout": mock_output,
            "stderr": "",
            "duration_seconds": 0.1,
            "executed_at": chrono::Utc::now().to_rfc3339()
        }))
    }
}

/// Type-safe tool execution function
///
/// This function takes strongly-typed tool arguments and executes the appropriate tool.
/// It provides compile-time guarantees that the tool arguments are valid.
pub async fn execute_tool_type_safe(tool_args: ToolArgs) -> ToolResult<Value> {
    match tool_args {
        ToolArgs::ClusterPing(args) => {
            let tool = ClusterPingTool;
            TypeSafeMcpTool::execute(&tool, args).await
        }
        ToolArgs::ClusterStatus(args) => {
            let tool = ClusterStatusTool;
            TypeSafeMcpTool::execute(&tool, args).await
        }
        ToolArgs::ServiceStatus(args) => {
            let tool = ServiceStatusTool;
            TypeSafeMcpTool::execute(&tool, args).await
        }
        ToolArgs::ShellCommand(args) => {
            let tool = ShellCommandTool;
            TypeSafeMcpTool::execute(&tool, args).await
        }
        // Add other tools as they're implemented
        _ => Err(TypeSafeError::<error_contexts::Tool>::tool_not_found(
            tool_args.tool_name().to_string(),
            MessageId::Number(0),
        )),
    }
}

/// Parse JSON parameters into strongly-typed arguments
///
/// This function bridges the gap between raw JSON and type-safe arguments,
/// providing validation at the parsing stage.
pub fn parse_tool_arguments(tool_name: &str, params: Value) -> Result<ToolArgs, String> {
    match tool_name {
        "cluster_ping" => {
            let args = ClusterPingArgs::default();
            Ok(ToolArgs::ClusterPing(args))
        }
        "cluster_status" => {
            let node = if let Some(node_str) = params.get("node").and_then(|v| v.as_str()) {
                Some(NodeName::new(node_str).map_err(|e| e.to_string())?)
            } else {
                None
            };
            let args = ClusterStatusArgs { node };
            Ok(ToolArgs::ClusterStatus(args))
        }
        "service_status" => {
            let service_str = params
                .get("service")
                .and_then(|v| v.as_str())
                .ok_or("Missing required parameter: service")?;

            let service = ServiceName::new(service_str).map_err(|e| e.to_string())?;

            let node = if let Some(node_str) = params.get("node").and_then(|v| v.as_str()) {
                Some(NodeName::new(node_str).map_err(|e| e.to_string())?)
            } else {
                None
            };

            let args = ServiceStatusArgs { service, node };
            Ok(ToolArgs::ServiceStatus(args))
        }
        "shell_command" => {
            let command_str = params
                .get("command")
                .and_then(|v| v.as_str())
                .ok_or("Missing required parameter: command")?;

            let command = ShellCommand::new(command_str).map_err(|e| e.to_string())?;

            let node = if let Some(node_str) = params.get("node").and_then(|v| v.as_str()) {
                Some(NodeName::new(node_str).map_err(|e| e.to_string())?)
            } else {
                None
            };

            let as_root = params.get("as_root").and_then(|v| v.as_bool());
            let timeout = params
                .get("timeout")
                .and_then(|v| v.as_u64())
                .map(|t| t as u32);

            let args = ShellCommandArgs {
                command,
                node,
                as_root,
                timeout,
            };
            Ok(ToolArgs::ShellCommand(args))
        }
        _ => Err(format!("unsupported tool '{tool_name}'")),
    }
}
