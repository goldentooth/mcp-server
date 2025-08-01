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

/// Default implementation of cluster operations
#[derive(Default)]
pub struct DefaultClusterOperations;

impl DefaultClusterOperations {
    pub fn new() -> Self {
        Self
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
impl ClusterOperations for DefaultClusterOperations {
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
            .map_err(|e| {
                ClusterOperationError::NetworkError(format!("HTTP client error: {}", e))
            })?;

        let url = format!("http://{}:9100/metrics", ip_str);
        let response = client.get(&url).send().await.map_err(|e| {
            ClusterOperationError::NetworkError(format!(
                "Failed to connect to node_exporter on {}: {}",
                node, e
            ))
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
            ClusterOperationError::NetworkError(format!(
                "Failed to read metrics from {}: {}",
                node, e
            ))
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
        use futures::future::join_all;

        let nodes_to_check: Vec<&str> = if let Some(specific_node) = node {
            vec![specific_node]
        } else {
            NODE_IPS.keys().copied().collect()
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| {
                ClusterOperationError::NetworkError(format!("HTTP client error: {}", e))
            })?;

        // Query all specified nodes in parallel
        let query_futures: Vec<_> = nodes_to_check
            .into_iter()
            .map(|node_name| {
                let client = client.clone();
                let service_name = service.to_string();
                async move {
                    let ip_str = NODE_IPS.get(node_name).copied().unwrap_or("127.0.0.1");
                    let url = format!("http://{}:9100/metrics", ip_str);

                    match client.get(&url).send().await {
                        Ok(response) if response.status().is_success() => {
                            match response.text().await {
                                Ok(metrics_text) => self.parse_service_status_from_metrics(
                                    node_name,
                                    &service_name,
                                    &metrics_text,
                                ),
                                Err(_) => ServiceStatus {
                                    name: service_name,
                                    node: node_name.to_string(),
                                    is_active: false,
                                    is_enabled: false,
                                    uptime: None,
                                },
                            }
                        }
                        _ => ServiceStatus {
                            name: service_name,
                            node: node_name.to_string(),
                            is_active: false,
                            is_enabled: false,
                            uptime: None,
                        },
                    }
                }
            })
            .collect();

        let results = join_all(query_futures).await;
        Ok(results)
    }

    async fn get_resource_usage(
        &self,
        node: Option<&str>,
    ) -> Result<HashMap<String, ResourceUsage>, ClusterOperationError> {
        use futures::future::join_all;

        let nodes_to_check: Vec<&str> = if let Some(specific_node) = node {
            vec![specific_node]
        } else {
            NODE_IPS.keys().copied().collect()
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| {
                ClusterOperationError::NetworkError(format!("HTTP client error: {}", e))
            })?;

        // Query all specified nodes in parallel
        let query_futures: Vec<_> = nodes_to_check
            .into_iter()
            .map(|node_name| {
                let client = client.clone();
                async move {
                    let ip_str = NODE_IPS.get(node_name).copied().unwrap_or("127.0.0.1");
                    let url = format!("http://{}:9100/metrics", ip_str);

                    match client.get(&url).send().await {
                        Ok(response) if response.status().is_success() => {
                            match response.text().await {
                                Ok(metrics_text) => {
                                    match self.parse_resource_usage_from_metrics(&metrics_text) {
                                        Ok(resource_usage) => {
                                            Some((node_name.to_string(), resource_usage))
                                        }
                                        Err(_) => None,
                                    }
                                }
                                Err(_) => None,
                            }
                        }
                        _ => None,
                    }
                }
            })
            .collect();

        let results = join_all(query_futures).await;
        let mut resource_map = HashMap::new();

        for result in results.into_iter().flatten() {
            resource_map.insert(result.0, result.1);
        }

        Ok(resource_map)
    }
}

impl DefaultClusterOperations {
    /// Parse node_exporter metrics to extract uptime and load averages
    /// Returns (uptime_string, load_average_tuple)
    fn parse_node_exporter_metrics(
        &self,
        metrics_text: &str,
    ) -> Result<MetricsParseResult, ClusterOperationError> {
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
            } else if line.starts_with("node_load5 ") {
                if let Some(value_str) = line.split_whitespace().nth(1) {
                    load5 = value_str.parse().ok();
                }
            } else if line.starts_with("node_load15 ") {
                if let Some(value_str) = line.split_whitespace().nth(1) {
                    load15 = value_str.parse().ok();
                }
            }
        }

        // Calculate uptime from boot time
        let uptime = if let Some(boot_timestamp) = boot_time {
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| {
                    ClusterOperationError::ParseError(format!("System time error: {}", e))
                })?
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

    /// Parse systemd service status from node_exporter metrics
    /// Looks for node_systemd_unit_state metrics to determine service status
    fn parse_service_status_from_metrics(
        &self,
        node_name: &str,
        service_name: &str,
        metrics_text: &str,
    ) -> ServiceStatus {
        let mut is_active = false;
        let mut is_enabled = false;
        let mut start_time: Option<f64> = None;

        // Look for systemd unit state metrics
        // Format: node_systemd_unit_state{name="service.service",state="active",type="service"} 1
        for line in metrics_text.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }

            // Check for service state (active/inactive)
            if line.starts_with("node_systemd_unit_state{")
                && line.contains(&format!("name=\"{}.service\"", service_name))
                && line.contains("state=\"active\"")
                && line.ends_with(" 1")
            {
                is_active = true;
            }

            // Check for service enabled state
            if line.starts_with("node_systemd_unit_state{")
                && line.contains(&format!("name=\"{}.service\"", service_name))
                && line.contains("state=\"enabled\"")
                && line.ends_with(" 1")
            {
                is_enabled = true;
            }

            // Look for service start time if available
            // Format: node_systemd_system_running 1704067200
            if line.starts_with(&format!(
                "node_systemd_service_start_time_seconds{{name=\"{}.service\"}}",
                service_name
            )) {
                if let Some(value_str) = line.split_whitespace().nth(1) {
                    start_time = value_str.parse().ok();
                }
            }
        }

        // Calculate uptime if we have start time
        let uptime = if let Some(start_timestamp) = start_time {
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as f64;

            let uptime_seconds = current_time - start_timestamp;
            if uptime_seconds > 0.0 {
                Some(format_uptime(uptime_seconds as u64))
            } else {
                None
            }
        } else {
            None
        };

        ServiceStatus {
            name: service_name.to_string(),
            node: node_name.to_string(),
            is_active,
            is_enabled,
            uptime,
        }
    }

    /// Parse memory and disk usage from node_exporter metrics
    fn parse_resource_usage_from_metrics(
        &self,
        metrics_text: &str,
    ) -> Result<ResourceUsage, ClusterOperationError> {
        let mut memory_total: Option<u64> = None;
        let mut memory_available: Option<u64> = None;
        let mut filesystems: HashMap<String, (f32, f32, String)> = HashMap::new(); // (total_gb, avail_gb, mount)

        for line in metrics_text.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }

            // Parse memory metrics (in bytes)
            if line.starts_with("node_memory_MemTotal_bytes ") {
                if let Some(value_str) = line.split_whitespace().nth(1) {
                    if let Ok(bytes) = value_str.parse::<u64>() {
                        memory_total = Some(bytes / 1_048_576); // Convert to MB
                    }
                }
            } else if line.starts_with("node_memory_MemAvailable_bytes ") {
                if let Some(value_str) = line.split_whitespace().nth(1) {
                    if let Ok(bytes) = value_str.parse::<u64>() {
                        memory_available = Some(bytes / 1_048_576); // Convert to MB
                    }
                }
            }
            // Parse filesystem metrics (in bytes)
            else if line.starts_with("node_filesystem_size_bytes{") {
                if let Some(device) = extract_label_value(line, "device") {
                    if let Some(mountpoint) = extract_label_value(line, "mountpoint") {
                        if let Some(value_str) = line.split_whitespace().last() {
                            if let Ok(bytes) = value_str.parse::<u64>() {
                                let total_gb = bytes as f32 / 1_073_741_824.0; // Convert to GB
                                filesystems
                                    .entry(device)
                                    .or_insert((0.0, 0.0, mountpoint))
                                    .0 = total_gb;
                            }
                        }
                    }
                }
            } else if line.starts_with("node_filesystem_avail_bytes{") {
                if let Some(device) = extract_label_value(line, "device") {
                    if let Some(mountpoint) = extract_label_value(line, "mountpoint") {
                        if let Some(value_str) = line.split_whitespace().last() {
                            if let Ok(bytes) = value_str.parse::<u64>() {
                                let avail_gb = bytes as f32 / 1_073_741_824.0; // Convert to GB
                                filesystems
                                    .entry(device.clone())
                                    .or_insert((0.0, 0.0, mountpoint))
                                    .1 = avail_gb;
                            }
                        }
                    }
                }
            }
        }

        // Build memory usage
        let memory = if let (Some(total), Some(available)) = (memory_total, memory_available) {
            let used = total.saturating_sub(available);
            let percent_used = if total > 0 {
                (used as f32 / total as f32) * 100.0
            } else {
                0.0
            };

            MemoryUsage {
                total_mb: total,
                used_mb: used,
                free_mb: available,
                percent_used,
            }
        } else {
            return Err(ClusterOperationError::ParseError(
                "Could not parse memory metrics".to_string(),
            ));
        };

        // Build disk usage from filesystems
        let disk: Vec<DiskUsage> = filesystems
            .into_iter()
            .filter(|(device, _)| device.starts_with("/dev/")) // Only real devices
            .map(|(filesystem, (total_gb, avail_gb, mount_point))| {
                let used_gb = total_gb - avail_gb;
                let percent_used = if total_gb > 0.0 {
                    (used_gb / total_gb) * 100.0
                } else {
                    0.0
                };

                DiskUsage {
                    filesystem,
                    total_gb,
                    used_gb,
                    available_gb: avail_gb,
                    percent_used,
                    mount_point,
                }
            })
            .collect();

        Ok(ResourceUsage { memory, disk })
    }
}

/// Extract label value from Prometheus metrics line
/// Example: extract_label_value('node_filesystem_size_bytes{device="/dev/sda1",mountpoint="/"} 123', "device") -> Some("/dev/sda1")
fn extract_label_value(line: &str, label: &str) -> Option<String> {
    let pattern = format!("{}=\"", label);
    if let Some(start_pos) = line.find(&pattern) {
        let value_start = start_pos + pattern.len();
        if let Some(end_pos) = line[value_start..].find('"') {
            return Some(line[value_start..value_start + end_pos].to_string());
        }
    }
    None
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

/// Mock implementation of ClusterOperations for testing
/// Available when testing to avoid real network calls
#[cfg(test)]
pub struct MockClusterOperations;

#[cfg(test)]
#[async_trait]
impl ClusterOperations for MockClusterOperations {
    async fn ping_all_nodes(&self) -> Result<Vec<NodeStatus>, ClusterOperationError> {
        // Return mock data for all 13 nodes
        let nodes = vec![
            NodeStatus {
                name: "allyrion".to_string(),
                is_online: true,
                uptime: Some("5 days, 3:15".to_string()),
                load_average: Some((0.15, 0.20, 0.18)),
            },
            NodeStatus {
                name: "bettley".to_string(),
                is_online: true,
                uptime: Some("3 days, 12:30".to_string()),
                load_average: Some((0.25, 0.30, 0.35)),
            },
            NodeStatus {
                name: "velaryon".to_string(),
                is_online: true,
                uptime: Some("1 days, 8:45".to_string()),
                load_average: Some((0.10, 0.15, 0.12)),
            },
            // Add a few more for realism
            NodeStatus {
                name: "cargyll".to_string(),
                is_online: true,
                uptime: Some("2 days, 6:20".to_string()),
                load_average: Some((0.05, 0.08, 0.10)),
            },
        ];
        Ok(nodes)
    }

    async fn get_node_status(&self, node: &str) -> Result<NodeStatus, ClusterOperationError> {
        Ok(NodeStatus {
            name: node.to_string(),
            is_online: true,
            uptime: Some("5 days, 3:15".to_string()),
            load_average: Some((0.15, 0.20, 0.18)),
        })
    }

    async fn get_service_status(
        &self,
        service: &str,
        node: Option<&str>,
    ) -> Result<Vec<ServiceStatus>, ClusterOperationError> {
        let nodes = if let Some(n) = node {
            vec![n.to_string()]
        } else {
            vec!["allyrion".to_string(), "bettley".to_string()]
        };

        let mut statuses = Vec::new();
        for node_name in nodes {
            statuses.push(ServiceStatus {
                name: service.to_string(),
                node: node_name,
                is_active: true,
                is_enabled: true,
                uptime: Some("2h 30m".to_string()),
            });
        }
        Ok(statuses)
    }

    async fn get_resource_usage(
        &self,
        node: Option<&str>,
    ) -> Result<HashMap<String, ResourceUsage>, ClusterOperationError> {
        let mut result = HashMap::new();
        let node_name = node.unwrap_or("allyrion").to_string();

        result.insert(
            node_name.clone(),
            ResourceUsage {
                memory: MemoryUsage {
                    total_mb: 8192,
                    used_mb: 2048,
                    free_mb: 6144,
                    percent_used: 25.0,
                },
                disk: vec![DiskUsage {
                    filesystem: "/dev/sda1".to_string(),
                    total_gb: 500.0,
                    used_gb: 100.0,
                    available_gb: 400.0,
                    percent_used: 20.0,
                    mount_point: "/".to_string(),
                }],
            },
        );
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

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
        let cluster_ops = DefaultClusterOperations::new();

        // Test TCP "ping" to localhost on a port that should be closed
        let localhost = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let timeout = Duration::from_millis(100);

        // This should fail quickly for a closed port
        let result = cluster_ops.tcp_ping(localhost, 65432, timeout).await;
        assert!(!result, "TCP ping to closed port should fail");
    }

    #[tokio::test]
    async fn test_ping_single_node_invalid_ip() {
        let cluster_ops = DefaultClusterOperations::new();

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
        let cluster_ops = DefaultClusterOperations::new();

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
        let cluster_ops = DefaultClusterOperations::new();

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
        let cluster_ops = DefaultClusterOperations::new();

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
        let cluster_ops = DefaultClusterOperations::new();

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
        let cluster_ops = DefaultClusterOperations::new();

        let result = cluster_ops.parse_node_exporter_metrics("");
        assert!(result.is_ok());

        let (uptime, load_average) = result.unwrap();
        assert_eq!(uptime, None);
        assert_eq!(load_average, None);
    }

    #[test]
    fn test_parse_node_exporter_metrics_comments_only() {
        let cluster_ops = DefaultClusterOperations::new();

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

    #[tokio::test]
    async fn test_mock_cluster_operations() {
        let mock_ops = MockClusterOperations;
        let result = mock_ops.ping_all_nodes().await;
        assert!(result.is_ok());
        let nodes = result.unwrap();
        assert_eq!(nodes.len(), 4); // We mock 4 nodes
        assert_eq!(nodes[0].name, "allyrion");
    }
}
