use std::time::Duration;
use tokio::process::Command;

/// SSH client for cluster operations
pub struct ClusterClient {
    ssh_user: String,
    #[allow(dead_code)]
    ssh_key_path: Option<String>,
    #[allow(dead_code)]
    timeout: Duration,
}

impl ClusterClient {
    pub fn new() -> Self {
        Self {
            ssh_user: "goldentooth".to_string(),
            ssh_key_path: None,
            timeout: Duration::from_secs(30),
        }
    }

    /// Execute command on a specific node via SSH
    pub async fn exec_on_node(
        &self,
        node: &str,
        command: &str,
        as_root: bool,
    ) -> Result<CommandResult, String> {
        // Use mock data in CI or when explicitly requested
        if std::env::var("GOLDENTOOTH_MOCK_SSH").is_ok()
            || std::env::var("CI").is_ok()
            || std::env::var("GITHUB_ACTIONS").is_ok()
        {
            return Ok(self.mock_command_result(node, command, as_root));
        }
        let full_command = if as_root {
            format!("sudo {command}")
        } else {
            command.to_string()
        };

        let mut ssh_cmd = Command::new("ssh");
        ssh_cmd
            .arg("-o")
            .arg("ConnectTimeout=5")
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg("-o")
            .arg("UserKnownHostsFile=/dev/null")
            .arg(format!("{}@{}.nodes.goldentooth.net", self.ssh_user, node))
            .arg(&full_command);

        let output = ssh_cmd
            .output()
            .await
            .map_err(|e| format!("SSH execution failed: {e}"))?;

        Ok(CommandResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            success: output.status.success(),
        })
    }

    /// Ping a node to check connectivity
    pub async fn ping_node(&self, node: &str) -> Result<PingResult, String> {
        // Use mock data in CI or when explicitly requested
        if std::env::var("GOLDENTOOTH_MOCK_SSH").is_ok()
            || std::env::var("CI").is_ok()
            || std::env::var("GITHUB_ACTIONS").is_ok()
        {
            return Ok(PingResult {
                icmp_reachable: true,
                tcp_port_22_open: true,
                ping_time_ms: 1.5,
                status: "reachable".to_string(),
            });
        }
        let hostname = format!("{node}.nodes.goldentooth.net");

        // Test ICMP ping
        let ping_cmd = Command::new("ping")
            .arg("-c")
            .arg("1")
            .arg("-W")
            .arg("5000")
            .arg(&hostname)
            .output()
            .await
            .map_err(|e| format!("Ping command failed: {e}"))?;

        let icmp_reachable = ping_cmd.status.success();
        let ping_time_ms = if icmp_reachable {
            // Parse ping time from output
            let stdout = String::from_utf8_lossy(&ping_cmd.stdout);
            parse_ping_time(&stdout).unwrap_or(0.0)
        } else {
            0.0
        };

        // Test SSH connectivity (TCP port 22)
        let ssh_test = Command::new("nc")
            .arg("-z")
            .arg("-w")
            .arg("5")
            .arg(&hostname)
            .arg("22")
            .output()
            .await
            .map_err(|e| format!("SSH test failed: {e}"))?;

        let tcp_port_22_open = ssh_test.status.success();

        Ok(PingResult {
            icmp_reachable,
            tcp_port_22_open,
            ping_time_ms,
            status: if icmp_reachable && tcp_port_22_open {
                "reachable".to_string()
            } else {
                "unreachable".to_string()
            },
        })
    }

    /// Get node status via node_exporter metrics
    pub async fn get_node_status(&self, node: &str) -> Result<NodeStatus, String> {
        // Use mock data in CI or when explicitly requested
        if std::env::var("GOLDENTOOTH_MOCK_SSH").is_ok()
            || std::env::var("CI").is_ok()
            || std::env::var("GITHUB_ACTIONS").is_ok()
        {
            return Ok(self.mock_node_status(node));
        }
        // Try to get metrics from node_exporter first
        let metrics_url = format!("http://{node}.nodes.goldentooth.net:9100/metrics");

        if let Ok(metrics) = self.fetch_node_exporter_metrics(&metrics_url).await {
            return Ok(metrics);
        }

        // Fallback to SSH-based status gathering
        let uptime_result = self.exec_on_node(node, "cat /proc/uptime", false).await;
        let loadavg_result = self.exec_on_node(node, "cat /proc/loadavg", false).await;
        let meminfo_result = self.exec_on_node(node, "cat /proc/meminfo", false).await;
        let df_result = self.exec_on_node(node, "df -h / | tail -n 1", false).await;

        let uptime_seconds = uptime_result
            .ok()
            .and_then(|r| {
                r.stdout
                    .split_whitespace()
                    .next()
                    .map(|s| s.parse::<f64>().unwrap_or(0.0))
            })
            .unwrap_or(0.0) as u64;

        let load_average = loadavg_result
            .ok()
            .and_then(|r| parse_load_average(&r.stdout))
            .unwrap_or_else(|| vec![0.0, 0.0, 0.0]);

        let (memory_used_mb, memory_total_mb) = meminfo_result
            .ok()
            .and_then(|r| parse_meminfo(&r.stdout))
            .unwrap_or((0, 2048));

        let memory_percentage = if memory_total_mb > 0 {
            (memory_used_mb as f64 / memory_total_mb as f64) * 100.0
        } else {
            0.0
        };

        let (disk_used_gb, disk_total_gb) = df_result
            .ok()
            .and_then(|r| parse_df_output(&r.stdout))
            .unwrap_or((0, 32));

        let disk_percentage = if disk_total_gb > 0 {
            (disk_used_gb as f64 / disk_total_gb as f64) * 100.0
        } else {
            0.0
        };

        let cpu_percentage = load_average.first().copied().unwrap_or(0.0) * 10.0;

        Ok(NodeStatus {
            hostname: node.to_string(),
            uptime_seconds,
            load_average,
            memory_usage: MemoryUsage {
                used_mb: memory_used_mb,
                total_mb: memory_total_mb,
                percentage: memory_percentage,
            },
            cpu_usage: CpuUsage {
                percentage: cpu_percentage, // Rough estimate
                temperature_c: 45.0,        // Mock temperature
            },
            disk_usage: DiskUsage {
                used_gb: disk_used_gb,
                total_gb: disk_total_gb,
                percentage: disk_percentage,
            },
            network: NetworkInfo {
                interface: "eth0".to_string(),
                ip_address: format!("10.4.0.{}", (node.len() * 10) % 254),
            },
            status: "healthy".to_string(),
        })
    }

    /// Check systemd service status on a node
    pub async fn get_service_status(
        &self,
        node: &str,
        service: &str,
    ) -> Result<ServiceStatus, String> {
        // Use mock data in CI or when explicitly requested
        if std::env::var("GOLDENTOOTH_MOCK_SSH").is_ok()
            || std::env::var("CI").is_ok()
            || std::env::var("GITHUB_ACTIONS").is_ok()
        {
            return Ok(self.mock_service_status(node, service));
        }

        // First check if the service unit file exists
        let exists_cmd = format!("systemctl cat {service} >/dev/null 2>&1");
        let exists_result = self.exec_on_node(node, &exists_cmd, false).await;

        if let Ok(result) = &exists_result {
            if !result.success {
                return Err(format!("Service {service} does not exist on node {node}"));
            }
        } else {
            return Err(format!(
                "Failed to check if service {service} exists on node {node}"
            ));
        }

        // Get service status
        let systemctl_cmd = format!("systemctl status {service} --no-pager -l");
        let status_result = self.exec_on_node(node, &systemctl_cmd, false).await;

        let (is_active, status_output) = match status_result {
            Ok(result) => (result.stdout.contains("Active: active"), result.stdout),
            Err(_) => (false, String::new()),
        };

        // Check if service is enabled (don't fail on error)
        let is_enabled_cmd = format!("systemctl is-enabled {service}");
        let is_enabled = match self.exec_on_node(node, &is_enabled_cmd, false).await {
            Ok(result) => {
                result.success
                    && !result.stdout.contains("disabled")
                    && !result.stdout.contains("masked")
            }
            Err(_) => false,
        };

        // Extract PID if available
        let pid = if is_active {
            parse_pid_from_status(&status_output).unwrap_or(0)
        } else {
            0
        };

        // Determine actual status from systemctl output
        let status = if status_output.contains("Active: active") {
            "active".to_string()
        } else if status_output.contains("Active: inactive") {
            "inactive".to_string()
        } else if status_output.contains("Active: failed") {
            "failed".to_string()
        } else {
            "unknown".to_string()
        };

        Ok(ServiceStatus {
            service: service.to_string(),
            status,
            enabled: is_enabled,
            running: is_active,
            pid,
            memory_usage_mb: 64,    // Mock value
            cpu_usage_percent: 2.5, // Mock value
            uptime_seconds: 3600,   // Mock value
            last_restart: "2024-01-01T12:00:00Z".to_string(),
            restart_count: 0,
        })
    }

    /// Get list of available services on a node
    pub async fn get_available_services(&self, node: &str) -> Result<Vec<String>, String> {
        if std::env::var("GOLDENTOOTH_MOCK_SSH").is_ok()
            || std::env::var("CI").is_ok()
            || std::env::var("GITHUB_ACTIONS").is_ok()
        {
            return Ok(vec!["consul".to_string(), "ssh".to_string()]);
        }

        let cmd = "systemctl list-units --type=service --state=loaded --no-legend | grep -E '(consul|nomad|vault|kubelet|ssh)' | awk '{print $1}' | sed 's/\\.service$//' | sort | uniq";
        let result = self.exec_on_node(node, cmd, false).await?;

        let services: Vec<String> = result
            .stdout
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter(|line| {
                !line.contains("cert-renewer")
                    && !line.contains("regenerate")
                    && !line.contains("sshswitch")
            })
            .map(|line| line.trim().to_string())
            .collect();

        Ok(services)
    }

    /// Fetch node_exporter metrics via HTTP
    async fn fetch_node_exporter_metrics(&self, _url: &str) -> Result<NodeStatus, String> {
        // This would use reqwest to fetch metrics, but for now we'll use a simpler approach
        // TODO: Implement proper Prometheus metrics parsing
        Err("Node exporter metrics not implemented yet".to_string())
    }

    /// Generate mock command result for testing
    fn mock_command_result(&self, node: &str, command: &str, _as_root: bool) -> CommandResult {
        let stdout = match command {
            "hostname" => node.to_string(),
            "uptime" => "12345.67 98765.43".to_string(),
            "cat /proc/uptime" => "12345.67 98765.43".to_string(),
            "cat /proc/loadavg" => "0.5 0.3 0.2 1/234 12345".to_string(),
            "cat /proc/meminfo" => "MemTotal: 2097152 kB\nMemAvailable: 1048576 kB".to_string(),
            _ if command.starts_with("df -h") => "/dev/sda1 30G 8G 20G 29% /".to_string(),
            _ if command.starts_with("systemctl status") => {
                "● service - Description\nActive: active (running)".to_string()
            }
            _ if command.starts_with("systemctl is-enabled") => "enabled".to_string(),
            _ => format!("Mock output for: {command}"),
        };

        CommandResult {
            exit_code: 0,
            stdout,
            stderr: String::new(),
            success: true,
        }
    }

    /// Generate mock node status for testing
    fn mock_node_status(&self, node: &str) -> NodeStatus {
        NodeStatus {
            hostname: node.to_string(),
            uptime_seconds: 86400,
            load_average: vec![0.5, 0.3, 0.2],
            memory_usage: MemoryUsage {
                used_mb: 1024,
                total_mb: 2048,
                percentage: 50.0,
            },
            cpu_usage: CpuUsage {
                percentage: 15.0,
                temperature_c: 45.5,
            },
            disk_usage: DiskUsage {
                used_gb: 8,
                total_gb: 30,
                percentage: 26.7,
            },
            network: NetworkInfo {
                interface: "eth0".to_string(),
                ip_address: format!("10.4.0.{}", (node.len() * 10) % 254),
            },
            status: "healthy".to_string(),
        }
    }

    /// Generate mock service status for testing
    fn mock_service_status(&self, _node: &str, service: &str) -> ServiceStatus {
        ServiceStatus {
            service: service.to_string(),
            status: "active".to_string(),
            enabled: true,
            running: true,
            pid: 12345,
            memory_usage_mb: 64,
            cpu_usage_percent: 2.5,
            uptime_seconds: 3600,
            last_restart: "2024-01-01T12:00:00Z".to_string(),
            restart_count: 0,
        }
    }
}

impl Default for ClusterClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a command execution
#[derive(Debug, Clone)]
pub struct CommandResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub success: bool,
}

/// Result of a ping operation
#[derive(Debug, Clone)]
pub struct PingResult {
    pub icmp_reachable: bool,
    pub tcp_port_22_open: bool,
    pub ping_time_ms: f64,
    pub status: String,
}

/// Node status information
#[derive(Debug, Clone)]
pub struct NodeStatus {
    pub hostname: String,
    pub uptime_seconds: u64,
    pub load_average: Vec<f64>,
    pub memory_usage: MemoryUsage,
    pub cpu_usage: CpuUsage,
    pub disk_usage: DiskUsage,
    pub network: NetworkInfo,
    pub status: String,
}

/// Memory usage information
#[derive(Debug, Clone)]
pub struct MemoryUsage {
    pub used_mb: u64,
    pub total_mb: u64,
    pub percentage: f64,
}

/// CPU usage information
#[derive(Debug, Clone)]
pub struct CpuUsage {
    pub percentage: f64,
    pub temperature_c: f64,
}

/// Disk usage information
#[derive(Debug, Clone)]
pub struct DiskUsage {
    pub used_gb: u64,
    pub total_gb: u64,
    pub percentage: f64,
}

/// Network information
#[derive(Debug, Clone)]
pub struct NetworkInfo {
    pub interface: String,
    pub ip_address: String,
}

/// Service status information
#[derive(Debug, Clone)]
pub struct ServiceStatus {
    pub service: String,
    pub status: String,
    pub enabled: bool,
    pub running: bool,
    pub pid: u32,
    pub memory_usage_mb: u64,
    pub cpu_usage_percent: f64,
    pub uptime_seconds: u64,
    pub last_restart: String,
    pub restart_count: u64,
}

// Helper functions for parsing command output

fn parse_ping_time(output: &str) -> Option<f64> {
    for line in output.lines() {
        if line.contains("time=") {
            if let Some(time_part) = line.split("time=").nth(1) {
                if let Some(time_str) = time_part.split_whitespace().next() {
                    return time_str.parse::<f64>().ok();
                }
            }
        }
    }
    None
}

fn parse_load_average(output: &str) -> Option<Vec<f64>> {
    let parts: Vec<&str> = output.split_whitespace().collect();
    if parts.len() >= 3 {
        let load1 = parts[0].parse::<f64>().ok()?;
        let load5 = parts[1].parse::<f64>().ok()?;
        let load15 = parts[2].parse::<f64>().ok()?;
        Some(vec![load1, load5, load15])
    } else {
        None
    }
}

fn parse_meminfo(output: &str) -> Option<(u64, u64)> {
    let mut mem_total = 0;
    let mut mem_available = 0;

    for line in output.lines() {
        if line.starts_with("MemTotal:") {
            if let Some(value) = line.split_whitespace().nth(1) {
                mem_total = value.parse::<u64>().unwrap_or(0) / 1024; // Convert KB to MB
            }
        } else if line.starts_with("MemAvailable:") {
            if let Some(value) = line.split_whitespace().nth(1) {
                mem_available = value.parse::<u64>().unwrap_or(0) / 1024; // Convert KB to MB
            }
        }
    }

    if mem_total > 0 {
        let mem_used = mem_total - mem_available;
        Some((mem_used, mem_total))
    } else {
        None
    }
}

fn parse_df_output(output: &str) -> Option<(u64, u64)> {
    let parts: Vec<&str> = output.split_whitespace().collect();
    if parts.len() >= 3 {
        // df output: Filesystem Size Used Avail Use% Mounted
        let size_str = parts[1].trim_end_matches('G');
        let used_str = parts[2].trim_end_matches('G');

        let total = size_str.parse::<u64>().ok()?;
        let used = used_str.parse::<u64>().ok()?;

        Some((used, total))
    } else {
        None
    }
}

fn parse_pid_from_status(output: &str) -> Option<u32> {
    for line in output.lines() {
        if line.contains("Main PID:") {
            if let Some(pid_part) = line.split("Main PID:").nth(1) {
                if let Some(pid_str) = pid_part.split_whitespace().next() {
                    return pid_str.parse::<u32>().ok();
                }
            }
        }
    }
    None
}
