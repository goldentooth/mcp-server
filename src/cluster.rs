use crate::command::CommandExecutor;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeStatus {
    pub name: String,
    pub is_online: bool,
    pub uptime: Option<String>,
    pub load_average: Option<(f32, f32, f32)>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub name: String,
    pub node: String,
    pub is_active: bool,
    pub is_enabled: bool,
    pub uptime: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub memory: MemoryUsage,
    pub disk: Vec<DiskUsage>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryUsage {
    pub total_mb: u64,
    pub used_mb: u64,
    pub free_mb: u64,
    pub percent_used: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiskUsage {
    pub filesystem: String,
    pub total_gb: f32,
    pub used_gb: f32,
    pub available_gb: f32,
    pub percent_used: f32,
    pub mount_point: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ClusterOperationError {
    #[error("Command failed: {0}")]
    CommandFailed(String),
    #[error("Parse error: {0}")]
    ParseError(String),
}

/// ClusterOperations trait for high-level cluster management
#[async_trait]
pub trait ClusterOperations: Send + Sync {
    async fn ping_all_nodes(&self) -> Result<Vec<NodeStatus>, ClusterOperationError>;
    async fn get_node_status(&self, node: &str) -> Result<NodeStatus, ClusterOperationError>;
    async fn get_service_status(
        &self,
        service: &str,
        node: Option<&str>,
    ) -> Result<Vec<ServiceStatus>, ClusterOperationError>;
    async fn get_resource_usage(
        &self,
        node: Option<&str>,
    ) -> Result<HashMap<String, ResourceUsage>, ClusterOperationError>;
}

/// Default implementation using CommandExecutor
pub struct DefaultClusterOperations<E: CommandExecutor> {
    executor: E,
}

impl<E: CommandExecutor> DefaultClusterOperations<E> {
    pub fn new(executor: E) -> Self {
        Self { executor }
    }
}

#[async_trait]
impl<E: CommandExecutor + Send + Sync> ClusterOperations for DefaultClusterOperations<E> {
    async fn ping_all_nodes(&self) -> Result<Vec<NodeStatus>, ClusterOperationError> {
        let output = self
            .executor
            .execute("goldentooth", &["ping", "all"])
            .await
            .map_err(ClusterOperationError::CommandFailed)?;

        // Parse the output
        let mut nodes = Vec::new();
        for line in output.lines() {
            if let Some((name, status)) = line.split_once(": ") {
                nodes.push(NodeStatus {
                    name: name.to_string(),
                    is_online: status.contains("online"),
                    uptime: None,
                    load_average: None,
                });
            }
        }

        Ok(nodes)
    }

    async fn get_node_status(&self, node: &str) -> Result<NodeStatus, ClusterOperationError> {
        let output = self
            .executor
            .execute("goldentooth", &["uptime", node])
            .await
            .map_err(ClusterOperationError::CommandFailed)?;

        // Parse uptime output
        // Format: "allyrion: 10:23:45 up 5 days, 3:15, 2 users, load average: 0.15, 0.20, 0.18"
        for line in output.lines() {
            if line.starts_with(&format!("{}: ", node)) {
                // Extract uptime - look for the part after "up " until the next comma
                let uptime = if let Some(up_index) = line.find(" up ") {
                    let after_up = &line[up_index + 4..];
                    // Find the next comma after "users"
                    if let Some(users_index) = after_up.find(" users") {
                        if let Some(comma_before_users) = after_up[..users_index].rfind(", ") {
                            Some(after_up[..comma_before_users].to_string())
                        } else {
                            Some(after_up[..users_index].trim().to_string())
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Extract load average
                let load_average = if let Some(la_index) = line.find("load average: ") {
                    let load_str = &line[la_index + 14..];
                    let loads: Vec<f32> = load_str
                        .split(", ")
                        .filter_map(|n| n.trim().parse().ok())
                        .collect();
                    if loads.len() == 3 {
                        Some((loads[0], loads[1], loads[2]))
                    } else {
                        None
                    }
                } else {
                    None
                };

                return Ok(NodeStatus {
                    name: node.to_string(),
                    is_online: true,
                    uptime,
                    load_average,
                });
            }
        }

        // If no matching line found, assume node is offline
        Ok(NodeStatus {
            name: node.to_string(),
            is_online: false,
            uptime: None,
            load_average: None,
        })
    }

    async fn get_service_status(
        &self,
        service: &str,
        node: Option<&str>,
    ) -> Result<Vec<ServiceStatus>, ClusterOperationError> {
        let node_arg = node.unwrap_or("all");
        let command = format!("systemctl status {}", service);

        let output = self
            .executor
            .execute("goldentooth", &["command", node_arg, &command])
            .await
            .map_err(ClusterOperationError::CommandFailed)?;

        let mut statuses = Vec::new();
        let mut current_node = String::new();

        for line in output.lines() {
            // Node header format: "=== nodename ==="
            if line.starts_with("=== ") && line.ends_with(" ===") {
                current_node = line
                    .trim_start_matches("=== ")
                    .trim_end_matches(" ===")
                    .to_string();
            } else if line.contains("Active: ") && !current_node.is_empty() {
                let is_active = line.contains("active (running)");

                statuses.push(ServiceStatus {
                    name: service.to_string(),
                    node: current_node.clone(),
                    is_active,
                    is_enabled: true, // Would need to parse more output for this
                    uptime: None,     // Would need to parse the "since" part
                });
            }
        }

        Ok(statuses)
    }

    async fn get_resource_usage(
        &self,
        node: Option<&str>,
    ) -> Result<HashMap<String, ResourceUsage>, ClusterOperationError> {
        let node_arg = node.unwrap_or("all");

        let output = self
            .executor
            .execute("goldentooth", &["command", node_arg, "free -h && df -h"])
            .await
            .map_err(ClusterOperationError::CommandFailed)?;

        let mut result = HashMap::new();
        let current_node = node.unwrap_or("unknown").to_string();

        // Parse memory usage from free -h output
        let mut memory_usage = None;
        let mut disk_usage = Vec::new();
        let mut in_df_section = false;

        for line in output.lines() {
            if line.starts_with("Mem:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    memory_usage = Some(MemoryUsage {
                        total_mb: parse_size_to_mb(parts[1]),
                        used_mb: parse_size_to_mb(parts[2]),
                        free_mb: parse_size_to_mb(parts[3]),
                        percent_used: 0.0, // Calculate below
                    });
                }
            } else if line.contains("Filesystem") && line.contains("Size") {
                in_df_section = true;
            } else if in_df_section && line.starts_with("/dev/") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    disk_usage.push(DiskUsage {
                        filesystem: parts[0].to_string(),
                        total_gb: parse_size_to_gb(parts[1]),
                        used_gb: parse_size_to_gb(parts[2]),
                        available_gb: parse_size_to_gb(parts[3]),
                        percent_used: parts[4].trim_end_matches('%').parse().unwrap_or(0.0),
                        mount_point: parts[5].to_string(),
                    });
                }
            }
        }

        if let Some(mut mem) = memory_usage {
            if mem.total_mb > 0 {
                mem.percent_used = (mem.used_mb as f32 / mem.total_mb as f32) * 100.0;
            }

            result.insert(
                current_node.clone(),
                ResourceUsage {
                    memory: mem,
                    disk: disk_usage,
                },
            );
        }

        Ok(result)
    }
}

/// Parse size strings like "7.6Gi", "255M", "59G" to MB
fn parse_size_to_mb(size_str: &str) -> u64 {
    if let Some(num_str) = size_str.strip_suffix("Gi") {
        (num_str.parse::<f32>().unwrap_or(0.0) * 1024.0) as u64
    } else if let Some(num_str) = size_str.strip_suffix("G") {
        (num_str.parse::<f32>().unwrap_or(0.0) * 1024.0) as u64
    } else if let Some(num_str) = size_str.strip_suffix("Mi") {
        num_str.parse().unwrap_or(0)
    } else if let Some(num_str) = size_str.strip_suffix("M") {
        num_str.parse().unwrap_or(0)
    } else if let Some(num_str) = size_str.strip_suffix("Ki") {
        num_str.parse::<u64>().unwrap_or(0) / 1024
    } else if let Some(num_str) = size_str.strip_suffix("K") {
        num_str.parse::<u64>().unwrap_or(0) / 1024
    } else {
        0
    }
}

/// Parse size strings to GB
fn parse_size_to_gb(size_str: &str) -> f32 {
    if let Some(num_str) = size_str.strip_suffix("G") {
        num_str.parse().unwrap_or(0.0)
    } else if let Some(num_str) = size_str.strip_suffix("M") {
        num_str.parse::<f32>().unwrap_or(0.0) / 1024.0
    } else if let Some(num_str) = size_str.strip_suffix("T") {
        num_str.parse::<f32>().unwrap_or(0.0) * 1024.0
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_size_to_mb() {
        assert_eq!(parse_size_to_mb("7.6Gi"), 7782);
        assert_eq!(parse_size_to_mb("2.1Gi"), 2150);
        assert_eq!(parse_size_to_mb("255M"), 255);
        assert_eq!(parse_size_to_mb("1024Ki"), 1);
    }

    #[test]
    fn test_parse_size_to_gb() {
        assert_eq!(parse_size_to_gb("59G"), 59.0);
        assert_eq!(parse_size_to_gb("255M"), 0.249_023_44);
        assert_eq!(parse_size_to_gb("2T"), 2048.0);
    }
}
