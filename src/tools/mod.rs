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
        use crate::cluster::ClusterClient;

        let client = ClusterClient::new();
        let mut nodes = HashMap::new();
        let mut reachable_count = 0;

        // Ping all known nodes
        for node in NodeName::valid_nodes() {
            match client.ping_node(node).await {
                Ok(result) => {
                    nodes.insert(
                        *node,
                        json!({
                            "status": result.status,
                            "ping_time_ms": result.ping_time_ms,
                            "icmp_reachable": result.icmp_reachable,
                            "tcp_port_22_open": result.tcp_port_22_open
                        }),
                    );

                    if result.icmp_reachable && result.tcp_port_22_open {
                        reachable_count += 1;
                    }
                }
                Err(error) => {
                    nodes.insert(
                        *node,
                        json!({
                            "status": "error",
                            "ping_time_ms": 0.0,
                            "icmp_reachable": false,
                            "tcp_port_22_open": false,
                            "error": error
                        }),
                    );
                }
            }
        }

        Ok(json!({
            "nodes": nodes,
            "summary": {
                "total_nodes": nodes.len(),
                "reachable_nodes": reachable_count,
                "unreachable_nodes": nodes.len() - reachable_count
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
        use crate::cluster::ClusterClient;

        let client = ClusterClient::new();
        let nodes_to_check: Vec<&str> = match &args.node {
            Some(node) => vec![node.as_str()],
            None => NodeName::valid_nodes().to_vec(),
        };

        let mut node_statuses = HashMap::new();

        for node in nodes_to_check {
            match client.get_node_status(node).await {
                Ok(status) => {
                    node_statuses.insert(
                        node,
                        json!({
                            "hostname": status.hostname,
                            "uptime_seconds": status.uptime_seconds,
                            "load_average": status.load_average,
                            "memory_usage": {
                                "used_mb": status.memory_usage.used_mb,
                                "total_mb": status.memory_usage.total_mb,
                                "percentage": status.memory_usage.percentage
                            },
                            "cpu_usage": {
                                "percentage": status.cpu_usage.percentage,
                                "temperature_c": status.cpu_usage.temperature_c
                            },
                            "disk_usage": {
                                "used_gb": status.disk_usage.used_gb,
                                "total_gb": status.disk_usage.total_gb,
                                "percentage": status.disk_usage.percentage
                            },
                            "network": {
                                "interface": status.network.interface,
                                "ip_address": status.network.ip_address
                            },
                            "status": status.status
                        }),
                    );
                }
                Err(error) => {
                    node_statuses.insert(
                        node,
                        json!({
                            "hostname": node,
                            "status": "error",
                            "error": error
                        }),
                    );
                }
            }
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
        use crate::cluster::ClusterClient;

        let client = ClusterClient::new();
        let nodes_to_check: Vec<&str> = match &args.node {
            Some(node) => vec![node.as_str()],
            None => NodeName::valid_nodes().to_vec(),
        };

        let mut node_statuses = HashMap::new();

        for node in nodes_to_check {
            match client.get_service_status(node, args.service.as_str()).await {
                Ok(status) => {
                    node_statuses.insert(
                        node,
                        json!({
                            "service": status.service,
                            "status": status.status,
                            "enabled": status.enabled,
                            "running": status.running,
                            "pid": status.pid,
                            "memory_usage_mb": status.memory_usage_mb,
                            "cpu_usage_percent": status.cpu_usage_percent,
                            "uptime_seconds": status.uptime_seconds,
                            "last_restart": status.last_restart,
                            "restart_count": status.restart_count
                        }),
                    );
                }
                Err(error) => {
                    node_statuses.insert(
                        node,
                        json!({
                            "service": args.service.as_str(),
                            "status": "error",
                            "error": error
                        }),
                    );
                }
            }
        }

        Ok(json!({
            "service": args.service.as_str(),
            "nodes": node_statuses,
            "queried_at": chrono::Utc::now().to_rfc3339()
        }))
    }
}

/// Type-safe resource usage tool implementation
pub struct ResourceUsageTool;

#[async_trait]
impl TypeSafeMcpTool<ResourceUsageArgs> for ResourceUsageTool {
    fn description(&self) -> &str {
        "Get memory and disk usage information for cluster nodes"
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

    async fn execute(&self, args: ResourceUsageArgs) -> ToolResult<Value> {
        use crate::cluster::ClusterClient;

        let client = ClusterClient::new();
        let nodes_to_check: Vec<&str> = match &args.node {
            Some(node) => vec![node.as_str()],
            None => NodeName::valid_nodes().to_vec(),
        };

        let mut node_resources = HashMap::new();

        for node in nodes_to_check {
            match client.get_node_status(node).await {
                Ok(status) => {
                    node_resources.insert(
                        node,
                        json!({
                            "hostname": status.hostname,
                            "memory": {
                                "used_mb": status.memory_usage.used_mb,
                                "total_mb": status.memory_usage.total_mb,
                                "percentage": status.memory_usage.percentage,
                                "free_mb": status.memory_usage.total_mb - status.memory_usage.used_mb
                            },
                            "disk": {
                                "used_gb": status.disk_usage.used_gb,
                                "total_gb": status.disk_usage.total_gb,
                                "percentage": status.disk_usage.percentage,
                                "free_gb": status.disk_usage.total_gb - status.disk_usage.used_gb
                            },
                            "cpu": {
                                "percentage": status.cpu_usage.percentage,
                                "temperature_c": status.cpu_usage.temperature_c,
                                "load_average": status.load_average
                            },
                            "uptime_seconds": status.uptime_seconds
                        }),
                    );
                }
                Err(error) => {
                    node_resources.insert(
                        node,
                        json!({
                            "hostname": node,
                            "status": "error",
                            "error": error
                        }),
                    );
                }
            }
        }

        Ok(json!({
            "nodes": node_resources,
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
        use crate::cluster::ClusterClient;

        // Validate command safety at execution time as well
        args.validate().map_err(|e| {
            TypeSafeError::<error_contexts::Argument>::from_tool_argument_error(
                e,
                MessageId::Number(0),
            )
            .map_context::<error_contexts::Tool>()
        })?;

        let client = ClusterClient::new();
        let target_node = args.node.as_ref().map(|n| n.as_str()).unwrap_or("allyrion");
        let as_root = args.as_root.unwrap_or(false);

        let start_time = std::time::Instant::now();

        match client
            .exec_on_node(target_node, args.command.as_str(), as_root)
            .await
        {
            Ok(result) => {
                let duration = start_time.elapsed().as_secs_f64();

                Ok(json!({
                    "command": args.command.as_str(),
                    "node": target_node,
                    "as_root": as_root,
                    "timeout": args.timeout.unwrap_or(30),
                    "exit_code": result.exit_code,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "success": result.success,
                    "duration_seconds": duration,
                    "executed_at": chrono::Utc::now().to_rfc3339()
                }))
            }
            Err(error) => {
                let duration = start_time.elapsed().as_secs_f64();

                Ok(json!({
                    "command": args.command.as_str(),
                    "node": target_node,
                    "as_root": as_root,
                    "timeout": args.timeout.unwrap_or(30),
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": error,
                    "success": false,
                    "duration_seconds": duration,
                    "executed_at": chrono::Utc::now().to_rfc3339()
                }))
            }
        }
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
        ToolArgs::ResourceUsage(args) => {
            let tool = ResourceUsageTool;
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
        "resource_usage" => {
            let node = if let Some(node_str) = params.get("node").and_then(|v| v.as_str()) {
                Some(NodeName::new(node_str).map_err(|e| e.to_string())?)
            } else {
                None
            };
            let args = ResourceUsageArgs { node };
            Ok(ToolArgs::ResourceUsage(args))
        }
        _ => Err(format!("unsupported tool '{tool_name}'")),
    }
}
