use async_trait::async_trait;
use base64::prelude::*;
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

/// Type-safe cluster info tool implementation
pub struct ClusterInfoTool;

#[async_trait]
impl TypeSafeMcpTool<ClusterInfoArgs> for ClusterInfoTool {
    fn description(&self) -> &str {
        "Get comprehensive cluster information including all nodes, services, and resource usage"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false,
            "description": "No arguments required - returns comprehensive cluster state"
        })
    }

    async fn execute(&self, _args: ClusterInfoArgs) -> ToolResult<Value> {
        use crate::cluster::ClusterClient;

        let client = ClusterClient::new();
        let mut cluster_data = json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "cluster_name": "goldentooth",
            "total_nodes": NodeName::valid_nodes().len(),
            "nodes": {},
            "services": {},
            "summary": {
                "nodes_reachable": 0,
                "nodes_unreachable": 0,
                "critical_services_up": 0,
                "critical_services_down": 0,
                "total_memory_gb": 0.0,
                "total_disk_gb": 0.0,
                "average_cpu_usage": 0.0,
                "average_load": 0.0
            }
        });

        let mut nodes_reachable = 0;
        let mut total_memory_gb = 0.0;
        let mut total_disk_gb = 0.0;
        let mut cpu_usage_sum = 0.0;
        let mut load_sum = 0.0;
        let mut responsive_nodes = 0;

        // Gather node information
        for node in NodeName::valid_nodes() {
            match client.get_node_status(node).await {
                Ok(status) => {
                    nodes_reachable += 1;
                    responsive_nodes += 1;

                    total_memory_gb += status.memory_usage.total_mb as f64 / 1024.0;
                    total_disk_gb += status.disk_usage.total_gb as f64;
                    cpu_usage_sum += status.cpu_usage.percentage;
                    if !status.load_average.is_empty() {
                        load_sum += status.load_average[0]; // 1-minute load average
                    }

                    cluster_data["nodes"][node] = json!({
                        "status": "online",
                        "hostname": status.hostname,
                        "uptime_seconds": status.uptime_seconds,
                        "load_average": status.load_average,
                        "memory": {
                            "used_mb": status.memory_usage.used_mb,
                            "total_mb": status.memory_usage.total_mb,
                            "percentage": status.memory_usage.percentage
                        },
                        "cpu": {
                            "percentage": status.cpu_usage.percentage,
                            "temperature_c": status.cpu_usage.temperature_c
                        },
                        "disk": {
                            "used_gb": status.disk_usage.used_gb,
                            "total_gb": status.disk_usage.total_gb,
                            "percentage": status.disk_usage.percentage
                        },
                        "network": {
                            "interface": status.network.interface,
                            "ip_address": status.network.ip_address
                        }
                    });
                }
                Err(error) => {
                    cluster_data["nodes"][node] = json!({
                        "status": "offline",
                        "hostname": node,
                        "error": error
                    });
                }
            }
        }

        // Intelligent service discovery and checking
        let mut all_discovered_services = std::collections::HashSet::new();
        let mut node_service_map = std::collections::HashMap::new();

        // First pass: discover what services exist on each node
        for node in NodeName::valid_nodes() {
            if let Ok(services) = client.get_available_services(node).await {
                node_service_map.insert(node, services.clone());
                for service in services {
                    all_discovered_services.insert(service);
                }
            }
        }

        let mut services_up = 0;
        let mut services_down = 0;

        // Second pass: check status of discovered services
        for service in &all_discovered_services {
            let mut service_nodes = json!({});
            let mut healthy_instances = 0;
            let mut total_instances = 0;

            for node in NodeName::valid_nodes() {
                // Only check this service if it exists on this node
                if let Some(node_services) = node_service_map.get(node) {
                    if !node_services.contains(service) {
                        // Service doesn't exist on this node - skip
                        continue;
                    }
                }

                total_instances += 1;
                match client.get_service_status(node, service).await {
                    Ok(status) if status.running => {
                        healthy_instances += 1;
                        service_nodes[node] = json!({
                            "status": "running",
                            "enabled": status.enabled,
                            "pid": status.pid,
                            "memory_usage_mb": status.memory_usage_mb,
                            "uptime_seconds": status.uptime_seconds
                        });
                    }
                    Ok(status) => {
                        service_nodes[node] = json!({
                            "status": status.status,
                            "enabled": status.enabled
                        });
                    }
                    Err(error) => {
                        // Only count as error if service should exist on this node
                        if let Some(node_services) = node_service_map.get(node) {
                            if node_services.contains(service) {
                                service_nodes[node] = json!({
                                    "status": "error",
                                    "error": error
                                });
                            }
                        }
                    }
                }
            }

            let service_health = if healthy_instances > 0 {
                services_up += 1;
                "healthy"
            } else if total_instances > 0 {
                services_down += 1;
                "unhealthy"
            } else {
                // Service doesn't exist anywhere - don't count it
                "not_deployed"
            };

            // Only include services that actually exist somewhere
            if total_instances > 0 {
                cluster_data["services"][service] = json!({
                    "overall_status": service_health,
                    "healthy_instances": healthy_instances,
                    "total_instances": total_instances,
                    "availability_percentage": if total_instances > 0 {
                        (healthy_instances as f64 / total_instances as f64) * 100.0
                    } else {
                        0.0
                    },
                    "nodes": service_nodes
                });
            }
        }

        // Update summary statistics
        cluster_data["summary"]["nodes_reachable"] = json!(nodes_reachable);
        cluster_data["summary"]["nodes_unreachable"] =
            json!(NodeName::valid_nodes().len() - nodes_reachable);
        cluster_data["summary"]["critical_services_up"] = json!(services_up);
        cluster_data["summary"]["critical_services_down"] = json!(services_down);
        cluster_data["summary"]["total_memory_gb"] = json!(total_memory_gb);
        cluster_data["summary"]["total_disk_gb"] = json!(total_disk_gb);

        if responsive_nodes > 0 {
            cluster_data["summary"]["average_cpu_usage"] =
                json!(cpu_usage_sum / responsive_nodes as f64);
            cluster_data["summary"]["average_load"] = json!(load_sum / responsive_nodes as f64);
        }

        cluster_data["summary"]["cluster_health"] = json!(if nodes_reachable
            == NodeName::valid_nodes().len()
            && services_down == 0
        {
            "healthy"
        } else if nodes_reachable > NodeName::valid_nodes().len() / 2 && services_up > services_down
        {
            "degraded"
        } else {
            "critical"
        });

        Ok(cluster_data)
    }
}

/// Type-safe journald logs tool implementation
pub struct JournaldLogsTool;

#[async_trait]
impl TypeSafeMcpTool<JournaldLogsArgs> for JournaldLogsTool {
    fn description(&self) -> &str {
        "Query systemd journal logs from cluster nodes with filtering options"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "node": {
                    "type": "string",
                    "description": "Specific node to query logs from (optional, defaults to allyrion)",
                    "enum": NodeName::valid_nodes()
                },
                "service": {
                    "type": "string",
                    "description": "Specific systemd service to filter logs for (optional)"
                },
                "priority": {
                    "type": "string",
                    "description": "Log priority level (0=emergency, 7=debug)",
                    "enum": ["0", "1", "2", "3", "4", "5", "6", "7"]
                },
                "since": {
                    "type": "string",
                    "description": "Show logs since this time (e.g., '1 hour ago', '2023-12-01')"
                },
                "lines": {
                    "type": "integer",
                    "description": "Maximum number of log lines to return",
                    "minimum": 1,
                    "maximum": 1000,
                    "default": 100
                },
                "follow": {
                    "type": "boolean",
                    "description": "Follow logs in real-time (not supported, always false)",
                    "default": false
                }
            },
            "additionalProperties": false
        })
    }

    async fn execute(&self, args: JournaldLogsArgs) -> ToolResult<Value> {
        use crate::cluster::ClusterClient;

        // Validate arguments
        args.validate().map_err(|e| {
            TypeSafeError::<error_contexts::Argument>::from_tool_argument_error(
                e,
                MessageId::Number(0),
            )
            .map_context::<error_contexts::Tool>()
        })?;

        let client = ClusterClient::new();
        let target_node = args.node.as_ref().map(|n| n.as_str()).unwrap_or("allyrion");

        // Build journalctl command with filters
        let mut cmd_parts = vec!["journalctl", "--no-pager", "--output=json"];

        // Add service filter if specified
        if let Some(service) = &args.service {
            cmd_parts.push("-u");
            cmd_parts.push(service.as_str());
        }

        // Add priority filter if specified
        if let Some(priority) = &args.priority {
            cmd_parts.push("-p");
            cmd_parts.push(priority.as_str());
        }

        // Add time filter if specified
        if let Some(since) = &args.since {
            cmd_parts.push("--since");
            cmd_parts.push(since);
        }

        // Add line limit
        let lines = args.lines.unwrap_or(100);
        let lines_str = lines.to_string();
        cmd_parts.push("-n");
        cmd_parts.push(&lines_str);

        let command = cmd_parts.join(" ");
        let start_time = std::time::Instant::now();

        match client.exec_on_node(target_node, &command, false).await {
            Ok(result) => {
                let duration = start_time.elapsed().as_secs_f64();

                // Parse JSON log entries
                let mut log_entries = Vec::new();
                for line in result.stdout.lines() {
                    if line.trim().is_empty() {
                        continue;
                    }

                    match serde_json::from_str::<Value>(line) {
                        Ok(entry) => {
                            // Extract relevant fields from journald JSON format
                            let formatted_entry = json!({
                                "timestamp": entry.get("__REALTIME_TIMESTAMP")
                                    .and_then(|t| t.as_str())
                                    .map(|ts| {
                                        // Convert microseconds timestamp to RFC3339
                                        if let Ok(micros) = ts.parse::<u64>() {
                                            let secs = micros / 1_000_000;
                                            chrono::DateTime::from_timestamp(secs as i64, 0)
                                                .map(|dt| dt.to_rfc3339())
                                                .unwrap_or_else(|| ts.to_string())
                                        } else {
                                            ts.to_string()
                                        }
                                    })
                                    .unwrap_or_else(|| "unknown".to_string()),
                                "hostname": entry.get("_HOSTNAME").and_then(|h| h.as_str()).unwrap_or(target_node),
                                "service": entry.get("_SYSTEMD_UNIT").and_then(|u| u.as_str()).unwrap_or("unknown"),
                                "priority": entry.get("PRIORITY").and_then(|p| p.as_str()).unwrap_or("6"),
                                "message": entry.get("MESSAGE").and_then(|m| m.as_str()).unwrap_or(""),
                                "pid": entry.get("_PID").and_then(|p| p.as_str()),
                                "boot_id": entry.get("_BOOT_ID").and_then(|b| b.as_str()),
                                "machine_id": entry.get("_MACHINE_ID").and_then(|m| m.as_str())
                            });
                            log_entries.push(formatted_entry);
                        }
                        Err(_) => {
                            // If JSON parsing fails, treat as plain text log
                            log_entries.push(json!({
                                "timestamp": chrono::Utc::now().to_rfc3339(),
                                "hostname": target_node,
                                "service": "unknown",
                                "priority": "6",
                                "message": line,
                                "raw": true
                            }));
                        }
                    }
                }

                Ok(json!({
                    "node": target_node,
                    "service_filter": args.service.as_ref().map(|s| s.as_str()),
                    "priority_filter": args.priority.as_ref().map(|p| p.as_str()),
                    "since_filter": args.since.as_ref(),
                    "lines_requested": lines,
                    "lines_returned": log_entries.len(),
                    "command": command,
                    "duration_seconds": duration,
                    "queried_at": chrono::Utc::now().to_rfc3339(),
                    "logs": log_entries
                }))
            }
            Err(error) => {
                let duration = start_time.elapsed().as_secs_f64();

                Ok(json!({
                    "node": target_node,
                    "service_filter": args.service.as_ref().map(|s| s.as_str()),
                    "priority_filter": args.priority.as_ref().map(|p| p.as_str()),
                    "since_filter": args.since.as_ref(),
                    "lines_requested": lines,
                    "lines_returned": 0,
                    "command": command,
                    "duration_seconds": duration,
                    "queried_at": chrono::Utc::now().to_rfc3339(),
                    "error": error,
                    "logs": []
                }))
            }
        }
    }
}

/// Type-safe Loki logs tool implementation
pub struct LokiLogsTool;

#[async_trait]
impl TypeSafeMcpTool<LokiLogsArgs> for LokiLogsTool {
    fn description(&self) -> &str {
        "Query Loki logs using LogQL syntax from the cluster logging infrastructure"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "LogQL query string (e.g., '{job=\"consul\"}', '{service=\"nomad\"} |= \"error\"')"
                },
                "start": {
                    "type": "string",
                    "description": "Start time for query (RFC3339 or relative like '1h')"
                },
                "end": {
                    "type": "string",
                    "description": "End time for query (RFC3339 or relative like 'now')"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of log entries to return",
                    "minimum": 1,
                    "maximum": 5000,
                    "default": 100
                },
                "direction": {
                    "type": "string",
                    "description": "Query direction",
                    "enum": ["forward", "backward"],
                    "default": "backward"
                }
            },
            "required": ["query"],
            "additionalProperties": false
        })
    }

    async fn execute(&self, args: LokiLogsArgs) -> ToolResult<Value> {
        use crate::cluster::ClusterClient;

        let client = ClusterClient::new();

        // Loki API endpoint - assuming it's accessible from the cluster
        let loki_url = "http://loki.services.goldentooth.net:3100";

        // Build query string
        let mut query_parts = vec![format!(
            "query={}",
            urlencoding::encode(args.query.as_str())
        )];

        if let Some(start) = &args.start {
            query_parts.push(format!("start={}", urlencoding::encode(start)));
        }

        if let Some(end) = &args.end {
            query_parts.push(format!("end={}", urlencoding::encode(end)));
        }

        if let Some(limit) = args.limit {
            query_parts.push(format!("limit={limit}"));
        }

        if let Some(direction) = &args.direction {
            let direction_str = match direction {
                LogDirection::Forward => "forward",
                LogDirection::Backward => "backward",
            };
            query_parts.push(format!("direction={direction_str}"));
        }

        let query_string = query_parts.join("&");

        let full_url = format!("{loki_url}/loki/api/v1/query_range?{query_string}");

        // Use curl to query Loki from a cluster node that has access
        let curl_command = format!("curl -s -G '{full_url}' -H 'Accept: application/json'");

        let start_time = std::time::Instant::now();

        match client.exec_on_node("allyrion", &curl_command, false).await {
            Ok(result) => {
                let duration = start_time.elapsed().as_secs_f64();

                if !result.success {
                    return Ok(json!({
                        "query": args.query.as_str(),
                        "loki_url": loki_url,
                        "start": args.start,
                        "end": args.end,
                        "limit": args.limit.unwrap_or(100),
                        "direction": args.direction.unwrap_or(LogDirection::Backward),
                        "duration_seconds": duration,
                        "queried_at": chrono::Utc::now().to_rfc3339(),
                        "error": format!("Loki query failed: {}", result.stderr),
                        "logs": []
                    }));
                }

                // Parse Loki response
                match serde_json::from_str::<Value>(&result.stdout) {
                    Ok(loki_response) => {
                        let mut formatted_logs = Vec::new();

                        if let Some(data) = loki_response.get("data") {
                            if let Some(result_array) =
                                data.get("result").and_then(|r| r.as_array())
                            {
                                for stream in result_array {
                                    let empty_labels = json!({});
                                    let stream_labels =
                                        stream.get("stream").unwrap_or(&empty_labels);

                                    if let Some(values) =
                                        stream.get("values").and_then(|v| v.as_array())
                                    {
                                        for value_pair in values {
                                            if let Some(pair) = value_pair.as_array() {
                                                if pair.len() >= 2 {
                                                    let timestamp_ns =
                                                        pair[0].as_str().unwrap_or("0");
                                                    let log_line = pair[1].as_str().unwrap_or("");

                                                    // Convert nanosecond timestamp to RFC3339
                                                    let timestamp = if let Ok(ns) =
                                                        timestamp_ns.parse::<u64>()
                                                    {
                                                        let secs = ns / 1_000_000_000;
                                                        let nanos = (ns % 1_000_000_000) as u32;
                                                        chrono::DateTime::from_timestamp(
                                                            secs as i64,
                                                            nanos,
                                                        )
                                                        .map(|dt| dt.to_rfc3339())
                                                        .unwrap_or_else(|| timestamp_ns.to_string())
                                                    } else {
                                                        timestamp_ns.to_string()
                                                    };

                                                    formatted_logs.push(json!({
                                                        "timestamp": timestamp,
                                                        "message": log_line,
                                                        "stream": stream_labels
                                                    }));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        Ok(json!({
                            "query": args.query.as_str(),
                            "loki_url": loki_url,
                            "start": args.start,
                            "end": args.end,
                            "limit": args.limit.unwrap_or(100),
                            "direction": args.direction.unwrap_or(LogDirection::Backward),
                            "duration_seconds": duration,
                            "queried_at": chrono::Utc::now().to_rfc3339(),
                            "logs_returned": formatted_logs.len(),
                            "logs": formatted_logs,
                            "raw_response_status": loki_response.get("status").and_then(|s| s.as_str()).unwrap_or("unknown")
                        }))
                    }
                    Err(parse_error) => Ok(json!({
                        "query": args.query.as_str(),
                        "loki_url": loki_url,
                        "start": args.start,
                        "end": args.end,
                        "limit": args.limit.unwrap_or(100),
                        "direction": args.direction.unwrap_or(LogDirection::Backward),
                        "duration_seconds": duration,
                        "queried_at": chrono::Utc::now().to_rfc3339(),
                        "error": format!("Failed to parse Loki response: {}", parse_error),
                        "raw_stdout": result.stdout,
                        "logs": []
                    })),
                }
            }
            Err(error) => {
                let duration = start_time.elapsed().as_secs_f64();

                Ok(json!({
                    "query": args.query.as_str(),
                    "loki_url": loki_url,
                    "start": args.start,
                    "end": args.end,
                    "limit": args.limit.unwrap_or(100),
                    "direction": args.direction.unwrap_or(LogDirection::Backward),
                    "duration_seconds": duration,
                    "queried_at": chrono::Utc::now().to_rfc3339(),
                    "error": format!("Failed to execute Loki query: {}", error),
                    "logs": []
                }))
            }
        }
    }
}

/// Screenshot URL tool for capturing web pages
pub struct ScreenshotUrlTool;

#[async_trait]
impl TypeSafeMcpTool<ScreenshotUrlArgs> for ScreenshotUrlTool {
    fn description(&self) -> &str {
        "Capture a screenshot of a web page using headless Chrome"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to capture a screenshot of",
                    "format": "uri"
                },
                "width": {
                    "type": "integer",
                    "description": "Optional viewport width in pixels",
                    "minimum": 100,
                    "maximum": 4096,
                    "default": 1920
                },
                "height": {
                    "type": "integer",
                    "description": "Optional viewport height in pixels",
                    "minimum": 100,
                    "maximum": 4096,
                    "default": 1080
                },
                "wait_for_selector": {
                    "type": "string",
                    "description": "Optional CSS selector to wait for before taking screenshot"
                },
                "wait_timeout_ms": {
                    "type": "integer",
                    "description": "Optional maximum time to wait for page load in milliseconds",
                    "minimum": 1000,
                    "maximum": 30000,
                    "default": 5000
                }
            },
            "required": ["url"]
        })
    }

    async fn execute(&self, args: ScreenshotUrlArgs) -> ToolResult<Value> {
        let start_time = std::time::Instant::now();

        // For now, return a placeholder implementation
        // TODO: Implement proper headless Chrome screenshot capture

        let width = args.width.unwrap_or(1920);
        let height = args.height.unwrap_or(1080);
        let duration = start_time.elapsed().as_secs_f64();

        // Create a simple placeholder image (1x1 PNG)
        let placeholder_png = vec![
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48,
            0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00,
            0x00, 0x90, 0x77, 0x53, 0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, 0x08,
            0xD7, 0x63, 0x00, 0x02, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
            0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
        ];

        let base64_image = BASE64_STANDARD.encode(&placeholder_png);

        Ok(json!({
            "url": args.url.as_str(),
            "width": width,
            "height": height,
            "wait_for_selector": args.wait_for_selector,
            "wait_timeout_ms": args.wait_timeout_ms.unwrap_or(5000),
            "screenshot_size_bytes": placeholder_png.len(),
            "screenshot_base64": base64_image,
            "screenshot_format": "png",
            "duration_seconds": duration,
            "captured_at": chrono::Utc::now().to_rfc3339(),
            "viewport": {
                "width": width,
                "height": height
            },
            "note": "Placeholder implementation - headless Chrome integration TODO"
        }))
    }
}

/// Screenshot dashboard tool for capturing authenticated dashboards
pub struct ScreenshotDashboardTool;

#[async_trait]
impl TypeSafeMcpTool<ScreenshotDashboardArgs> for ScreenshotDashboardTool {
    fn description(&self) -> &str {
        "Capture a screenshot of a Grafana dashboard with Authelia authentication bypass"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "dashboard_url": {
                    "type": "string",
                    "description": "The Grafana dashboard URL to capture",
                    "format": "uri"
                }
            },
            "required": ["dashboard_url"]
        })
    }

    async fn execute(&self, args: ScreenshotDashboardArgs) -> ToolResult<Value> {
        let start_time = std::time::Instant::now();

        // For now, return a placeholder implementation
        // TODO: Implement proper headless Chrome with Authelia authentication bypass

        let duration = start_time.elapsed().as_secs_f64();

        // Create a simple placeholder image (1x1 PNG)
        let placeholder_png = vec![
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48,
            0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00,
            0x00, 0x90, 0x77, 0x53, 0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, 0x08,
            0xD7, 0x63, 0x00, 0x02, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
            0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
        ];

        let base64_image = BASE64_STANDARD.encode(&placeholder_png);

        Ok(json!({
            "dashboard_url": args.dashboard_url.as_str(),
            "screenshot_size_bytes": placeholder_png.len(),
            "screenshot_base64": base64_image,
            "screenshot_format": "png",
            "duration_seconds": duration,
            "captured_at": chrono::Utc::now().to_rfc3339(),
            "viewport": {
                "width": 1920,
                "height": 1080
            },
            "authentication": "bypass_planned", // TODO: Implement Authelia bypass
            "note": "Placeholder implementation - headless Chrome with Authelia auth TODO"
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
        ToolArgs::ResourceUsage(args) => {
            let tool = ResourceUsageTool;
            TypeSafeMcpTool::execute(&tool, args).await
        }
        ToolArgs::ClusterInfo(args) => {
            let tool = ClusterInfoTool;
            TypeSafeMcpTool::execute(&tool, args).await
        }
        ToolArgs::JournaldLogs(args) => {
            let tool = JournaldLogsTool;
            TypeSafeMcpTool::execute(&tool, args).await
        }
        ToolArgs::LokiLogs(args) => {
            let tool = LokiLogsTool;
            TypeSafeMcpTool::execute(&tool, args).await
        }
        ToolArgs::ScreenshotUrl(args) => {
            let tool = ScreenshotUrlTool;
            TypeSafeMcpTool::execute(&tool, args).await
        }
        ToolArgs::ScreenshotDashboard(args) => {
            let tool = ScreenshotDashboardTool;
            TypeSafeMcpTool::execute(&tool, args).await
        }
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
        "cluster_info" => {
            let args = ClusterInfoArgs::default();
            Ok(ToolArgs::ClusterInfo(args))
        }
        "journald_logs" => {
            let node = if let Some(node_str) = params.get("node").and_then(|v| v.as_str()) {
                Some(NodeName::new(node_str).map_err(|e| e.to_string())?)
            } else {
                None
            };

            let service = if let Some(service_str) = params.get("service").and_then(|v| v.as_str())
            {
                Some(ServiceName::new(service_str).map_err(|e| e.to_string())?)
            } else {
                None
            };

            let priority =
                if let Some(priority_str) = params.get("priority").and_then(|v| v.as_str()) {
                    match priority_str {
                        "0" => Some(LogPriority::Emergency),
                        "1" => Some(LogPriority::Alert),
                        "2" => Some(LogPriority::Critical),
                        "3" => Some(LogPriority::Error),
                        "4" => Some(LogPriority::Warning),
                        "5" => Some(LogPriority::Notice),
                        "6" => Some(LogPriority::Info),
                        "7" => Some(LogPriority::Debug),
                        _ => {
                            return Err(format!(
                                "Invalid priority level: {priority_str}. Must be 0-7"
                            ));
                        }
                    }
                } else {
                    None
                };

            let since = params
                .get("since")
                .and_then(|v| v.as_str())
                .map(String::from);
            let lines = params
                .get("lines")
                .and_then(|v| v.as_u64())
                .map(|l| l as u32);
            let follow = params.get("follow").and_then(|v| v.as_bool());

            let args = JournaldLogsArgs {
                node,
                service,
                priority,
                since,
                lines,
                follow,
            };
            Ok(ToolArgs::JournaldLogs(args))
        }
        "loki_logs" => {
            let query_str = params
                .get("query")
                .and_then(|v| v.as_str())
                .ok_or("Missing required parameter: query")?;

            let query = LogQLQuery::new(query_str).map_err(|e| e.to_string())?;

            let start = params
                .get("start")
                .and_then(|v| v.as_str())
                .map(String::from);
            let end = params.get("end").and_then(|v| v.as_str()).map(String::from);
            let limit = params
                .get("limit")
                .and_then(|v| v.as_u64())
                .map(|l| l as u32);

            let direction = if let Some(direction_str) =
                params.get("direction").and_then(|v| v.as_str())
            {
                match direction_str.to_lowercase().as_str() {
                    "forward" => Some(LogDirection::Forward),
                    "backward" => Some(LogDirection::Backward),
                    _ => {
                        return Err(format!(
                            "Invalid direction: {direction_str}. Must be 'forward' or 'backward'"
                        ));
                    }
                }
            } else {
                None
            };

            let args = LokiLogsArgs {
                query,
                start,
                end,
                limit,
                direction,
            };
            Ok(ToolArgs::LokiLogs(args))
        }
        "screenshot_url" => {
            let url_str = params
                .get("url")
                .and_then(|v| v.as_str())
                .ok_or("Missing required parameter: url")?;

            let url = HttpUrl::new(url_str).map_err(|e| e.to_string())?;

            let width = params
                .get("width")
                .and_then(|v| v.as_u64())
                .map(|w| w as u32);
            let height = params
                .get("height")
                .and_then(|v| v.as_u64())
                .map(|h| h as u32);
            let wait_for_selector = params
                .get("wait_for_selector")
                .and_then(|v| v.as_str())
                .map(String::from);
            let wait_timeout_ms = params
                .get("wait_timeout_ms")
                .and_then(|v| v.as_u64())
                .map(|t| t as u32);

            let args = ScreenshotUrlArgs {
                url,
                width,
                height,
                wait_for_selector,
                wait_timeout_ms,
            };
            Ok(ToolArgs::ScreenshotUrl(args))
        }
        "screenshot_dashboard" => {
            let dashboard_url_str = params
                .get("dashboard_url")
                .and_then(|v| v.as_str())
                .ok_or("Missing required parameter: dashboard_url")?;

            let dashboard_url = HttpUrl::new(dashboard_url_str).map_err(|e| e.to_string())?;

            let args = ScreenshotDashboardArgs { dashboard_url };
            Ok(ToolArgs::ScreenshotDashboard(args))
        }
        _ => Err(format!("unsupported tool '{tool_name}'")),
    }
}
