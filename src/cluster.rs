use crate::command::CommandExecutor;
use async_trait::async_trait;
use lazy_static::lazy_static;
use ping::ping;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

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
    #[error("Network error: {0}")]
    NetworkError(String),
}

/// Type alias to simplify complex return type for metrics parsing
type MetricsParseResult = (Option<String>, Option<(f32, f32, f32)>);

lazy_static! {
    /// Static mapping of node names to IP addresses
    /// Based on the Ansible inventory host_vars
    static ref NODE_IPS: HashMap<&'static str, &'static str> = {
        let mut map = HashMap::new();
        // Raspberry Pi nodes
        map.insert("allyrion", "10.4.0.10");
        map.insert("bettley", "10.4.0.11");
        map.insert("cargyll", "10.4.0.12");
        map.insert("dalt", "10.4.0.13");
        map.insert("erenford", "10.4.0.14");
        map.insert("fenn", "10.4.0.15");
        map.insert("gardener", "10.4.0.16");
        map.insert("harlton", "10.4.0.17");
        map.insert("inchfield", "10.4.0.18");
        map.insert("jast", "10.4.0.19");
        map.insert("karstark", "10.4.0.20");
        map.insert("lipps", "10.4.0.21");
        // x86 GPU node
        map.insert("velaryon", "10.4.0.30");
        map
    };
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

    /// TCP "ping" - attempt to connect to a specific port to test connectivity
    async fn tcp_ping(&self, ip: IpAddr, port: u16, timeout_duration: Duration) -> bool {
        use tokio::net::TcpStream;
        use tokio::time::timeout;

        let addr = std::net::SocketAddr::new(ip, port);
        match timeout(timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => true,
            Ok(Err(_)) | Err(_) => false,
        }
    }

    /// Ping a single node with ICMP, falling back to TCP if needed
    async fn ping_single_node(
        &self,
        node_name: String,
        ip_str: String,
    ) -> Result<NodeStatus, ClusterOperationError> {
        let ip_addr = IpAddr::from_str(&ip_str).map_err(|e| {
            ClusterOperationError::NetworkError(format!("Invalid IP {}: {}", ip_str, e))
        })?;

        // Try ICMP ping first, fall back to TCP connect if it fails due to permissions
        let timeout = Duration::from_secs(2);
        let is_online = match ping(ip_addr, Some(timeout), None, None, None, None) {
            Ok(_) => true,
            Err(ping_err) => {
                // If ICMP fails (likely due to permissions), try TCP connect to SSH port (22)
                log::debug!(
                    "ICMP ping failed for {}: {}, trying TCP connect",
                    node_name,
                    ping_err
                );
                self.tcp_ping(ip_addr, 22, timeout).await
            }
        };

        Ok(NodeStatus {
            name: node_name,
            is_online,
            uptime: None,
            load_average: None,
        })
    }
}

#[async_trait]
impl<E: CommandExecutor + Send + Sync> ClusterOperations for DefaultClusterOperations<E> {
    async fn ping_all_nodes(&self) -> Result<Vec<NodeStatus>, ClusterOperationError> {
        use futures::future::join_all;

        let ping_futures: Vec<_> = NODE_IPS
            .iter()
            .map(|(node_name, ip_str)| {
                self.ping_single_node(node_name.to_string(), ip_str.to_string())
            })
            .collect();

        let results = join_all(ping_futures).await;
        results.into_iter().collect()
    }

    async fn get_node_status(&self, node: &str) -> Result<NodeStatus, ClusterOperationError> {
        let ip_str = NODE_IPS.get(node).ok_or_else(|| {
            ClusterOperationError::NetworkError(format!("Unknown node: {}", node))
        })?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| ClusterOperationError::NetworkError(format!("HTTP client error: {}", e)))?;

        let url = format!("http://{}:9100/metrics", ip_str);
        let response = client.get(&url).send().await.map_err(|e| {
            ClusterOperationError::NetworkError(format!("Failed to connect to node_exporter on {}: {}", node, e))
        })?;

        if !response.status().is_success() {
            return Ok(NodeStatus {
                name: node.to_string(),
                is_online: false,
                uptime: None,
                load_average: None,
            });
        }

        let metrics_text = response.text().await.map_err(|e| {
            ClusterOperationError::NetworkError(format!("Failed to read metrics from {}: {}", node, e))
        })?;

        let (uptime, load_average) = self.parse_node_exporter_metrics(&metrics_text)?;

        Ok(NodeStatus {
            name: node.to_string(),
            is_online: true,
            uptime,
            load_average,
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

impl<E: CommandExecutor> DefaultClusterOperations<E> {
    /// Parse node_exporter metrics to extract uptime and load averages  
    /// Returns (uptime_string, load_average_tuple)
    fn parse_node_exporter_metrics(&self, metrics_text: &str) -> Result<MetricsParseResult, ClusterOperationError> {
        let mut boot_time: Option<f64> = None;
        let mut load1: Option<f32> = None;
        let mut load5: Option<f32> = None;
        let mut load15: Option<f32> = None;

        for line in metrics_text.lines() {
            // Skip comments and empty lines
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }

            // Parse boot time: node_boot_time_seconds 1704067200
            if line.starts_with("node_boot_time_seconds ") {
                if let Some(value_str) = line.split_whitespace().nth(1) {
                    boot_time = value_str.parse().ok();
                }
            }
            // Parse load averages: node_load1 0.15
            else if line.starts_with("node_load1 ") {
                if let Some(value_str) = line.split_whitespace().nth(1) {
                    load1 = value_str.parse().ok();
                }
            }
            else if line.starts_with("node_load5 ") {
                if let Some(value_str) = line.split_whitespace().nth(1) {
                    load5 = value_str.parse().ok();
                }
            }
            else if line.starts_with("node_load15 ") {
                if let Some(value_str) = line.split_whitespace().nth(1) {
                    load15 = value_str.parse().ok();
                }
            }
        }

        // Calculate uptime from boot time
        let uptime = if let Some(boot_timestamp) = boot_time {
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| ClusterOperationError::ParseError(format!("System time error: {}", e)))?
                .as_secs() as f64;
            
            let uptime_seconds = current_time - boot_timestamp;
            if uptime_seconds > 0.0 {
                Some(format_uptime(uptime_seconds as u64))
            } else {
                None
            }
        } else {
            None
        };

        // Combine load averages
        let load_average = match (load1, load5, load15) {
            (Some(l1), Some(l5), Some(l15)) => Some((l1, l5, l15)),
            _ => None,
        };

        Ok((uptime, load_average))
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

/// Format uptime seconds into human-readable string like "5 days, 3:15"
fn format_uptime(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let minutes = (seconds % 3600) / 60;

    if days > 0 {
        format!("{} days, {}:{:02}", days, hours, minutes)
    } else {
        format!("{}:{:02}", hours, minutes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::MockCommandExecutor;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

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

    #[test]
    fn test_node_ips_static_map() {
        // Verify all expected nodes are present
        assert_eq!(NODE_IPS.len(), 13);

        // Test Pi nodes
        assert_eq!(NODE_IPS.get("allyrion"), Some(&"10.4.0.10"));
        assert_eq!(NODE_IPS.get("bettley"), Some(&"10.4.0.11"));
        assert_eq!(NODE_IPS.get("lipps"), Some(&"10.4.0.21"));

        // Test x86 GPU node
        assert_eq!(NODE_IPS.get("velaryon"), Some(&"10.4.0.30"));

        // Test non-existent node
        assert_eq!(NODE_IPS.get("nonexistent"), None);
    }

    #[tokio::test]
    async fn test_tcp_ping_localhost() {
        let executor = MockCommandExecutor::new();
        let cluster_ops = DefaultClusterOperations::new(executor);

        // Test TCP "ping" to localhost on a port that should be closed
        let localhost = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let timeout = Duration::from_millis(100);

        // This should fail quickly for a closed port
        let result = cluster_ops.tcp_ping(localhost, 65432, timeout).await;
        assert!(!result, "TCP ping to closed port should fail");
    }

    #[tokio::test]
    async fn test_ping_single_node_invalid_ip() {
        let executor = MockCommandExecutor::new();
        let cluster_ops = DefaultClusterOperations::new(executor);

        let result = cluster_ops
            .ping_single_node("test".to_string(), "invalid.ip".to_string())
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ClusterOperationError::NetworkError(msg) => {
                assert!(msg.contains("Invalid IP"));
            }
            _ => panic!("Expected NetworkError"),
        }
    }

    #[tokio::test]
    async fn test_ping_single_node_valid_format() {
        let executor = MockCommandExecutor::new();
        let cluster_ops = DefaultClusterOperations::new(executor);

        // Use localhost IP - this may or may not succeed depending on ICMP permissions
        // but should at least not error on IP parsing
        let result = cluster_ops
            .ping_single_node("localhost".to_string(), "127.0.0.1".to_string())
            .await;

        assert!(result.is_ok());
        let node_status = result.unwrap();
        assert_eq!(node_status.name, "localhost");
        assert!(node_status.uptime.is_none());
        assert!(node_status.load_average.is_none());
        // is_online may be true or false depending on system configuration
    }

    #[test]
    fn test_cluster_operation_error_variants() {
        let cmd_error = ClusterOperationError::CommandFailed("test".to_string());
        assert_eq!(format!("{}", cmd_error), "Command failed: test");

        let parse_error = ClusterOperationError::ParseError("test".to_string());
        assert_eq!(format!("{}", parse_error), "Parse error: test");

        let network_error = ClusterOperationError::NetworkError("test".to_string());
        assert_eq!(format!("{}", network_error), "Network error: test");
    }

    #[tokio::test]
    async fn test_ping_all_nodes_structure() {
        let executor = MockCommandExecutor::new();
        let cluster_ops = DefaultClusterOperations::new(executor);

        // This test verifies the structure and parallel execution
        // Individual pings may fail, but the overall structure should work
        let result = cluster_ops.ping_all_nodes().await;

        assert!(result.is_ok());
        let nodes = result.unwrap();
        assert_eq!(nodes.len(), 13);

        // Verify all expected node names are present
        let node_names: Vec<String> = nodes.iter().map(|n| n.name.clone()).collect();
        assert!(node_names.contains(&"allyrion".to_string()));
        assert!(node_names.contains(&"velaryon".to_string()));
    }

    #[test]
    fn test_format_uptime() {
        // Test various uptime durations
        assert_eq!(format_uptime(0), "0:00");
        assert_eq!(format_uptime(60), "0:01");
        assert_eq!(format_uptime(3600), "1:00");
        assert_eq!(format_uptime(3661), "1:01");
        assert_eq!(format_uptime(86400), "1 days, 0:00");
        assert_eq!(format_uptime(90061), "1 days, 1:01");
        assert_eq!(format_uptime(432000), "5 days, 0:00");
        assert_eq!(format_uptime(443700), "5 days, 3:15");
    }

    #[test]
    fn test_parse_node_exporter_metrics() {
        let executor = MockCommandExecutor::new();
        let cluster_ops = DefaultClusterOperations::new(executor);

        // Mock metrics text with boot time and load averages
        let metrics_text = r#"
# HELP node_boot_time_seconds Node boot time, in unixtime.
# TYPE node_boot_time_seconds gauge
node_boot_time_seconds 1704067200
# HELP node_load1 1m load average.
# TYPE node_load1 gauge
node_load1 0.15
# HELP node_load5 5m load average.
# TYPE node_load5 gauge
node_load5 0.20
# HELP node_load15 15m load average.
# TYPE node_load15 gauge
node_load15 0.18
# Other metrics...
node_memory_MemTotal_bytes 8589934592
"#;

        let result = cluster_ops.parse_node_exporter_metrics(metrics_text);
        assert!(result.is_ok());

        let (uptime, load_average) = result.unwrap();
        
        // Uptime should be calculated from boot time (will vary with current time)
        assert!(uptime.is_some());
        let uptime_str = uptime.unwrap();
        assert!(uptime_str.contains("days") || uptime_str.contains(":"));

        // Load averages should be parsed correctly
        assert_eq!(load_average, Some((0.15, 0.20, 0.18)));
    }

    #[test]
    fn test_parse_node_exporter_metrics_missing_data() {
        let executor = MockCommandExecutor::new();
        let cluster_ops = DefaultClusterOperations::new(executor);

        // Metrics with missing load data
        let metrics_text = r#"
node_boot_time_seconds 1704067200
node_load1 0.15
# Missing node_load5 and node_load15
"#;

        let result = cluster_ops.parse_node_exporter_metrics(metrics_text);
        assert!(result.is_ok());

        let (uptime, load_average) = result.unwrap();
        
        // Should have uptime but no complete load average
        assert!(uptime.is_some());
        assert_eq!(load_average, None);
    }

    #[test]
    fn test_parse_node_exporter_metrics_empty() {
        let executor = MockCommandExecutor::new();
        let cluster_ops = DefaultClusterOperations::new(executor);

        let result = cluster_ops.parse_node_exporter_metrics("");
        assert!(result.is_ok());

        let (uptime, load_average) = result.unwrap();
        assert_eq!(uptime, None);
        assert_eq!(load_average, None);
    }

    #[test]
    fn test_parse_node_exporter_metrics_comments_only() {
        let executor = MockCommandExecutor::new();
        let cluster_ops = DefaultClusterOperations::new(executor);

        let metrics_text = r#"
# HELP node_boot_time_seconds Node boot time, in unixtime.
# TYPE node_boot_time_seconds gauge
# This is just comments and help text
# No actual metrics
"#;

        let result = cluster_ops.parse_node_exporter_metrics(metrics_text);
        assert!(result.is_ok());

        let (uptime, load_average) = result.unwrap();
        assert_eq!(uptime, None);
        assert_eq!(load_average, None);
    }
}
