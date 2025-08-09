//! Strongly-typed tool argument definitions
//!
//! This module provides compile-time guarantees for tool arguments by defining
//! explicit structs for each tool's parameters. This replaces runtime validation
//! with type safety, making illegal states unrepresentable.

use serde::{Deserialize, Serialize};

/// Trait for type-safe tool arguments
pub trait ToolArguments {
    /// The name of the tool these arguments are for
    const TOOL_NAME: &'static str;

    /// Validate the arguments at the type level
    /// This method should only perform validations that cannot be expressed in the type system
    fn validate(&self) -> Result<(), ToolArgumentError> {
        Ok(())
    }
}

/// Errors that can occur during tool argument processing
#[derive(Debug, Clone, PartialEq)]
pub enum ToolArgumentError {
    /// A field value violates business logic constraints
    InvalidValue { field: String, reason: String },
    /// A security constraint was violated
    SecurityViolation { reason: String },
    /// A dependency constraint was not satisfied
    DependencyConstraint { reason: String },
}

impl std::fmt::Display for ToolArgumentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolArgumentError::InvalidValue { field, reason } => {
                write!(f, "Invalid value for field '{field}': {reason}")
            }
            ToolArgumentError::SecurityViolation { reason } => {
                write!(f, "Security violation: {reason}")
            }
            ToolArgumentError::DependencyConstraint { reason } => {
                write!(f, "Dependency constraint: {reason}")
            }
        }
    }
}

impl std::error::Error for ToolArgumentError {}

/// Arguments for the cluster_ping tool
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ClusterPingArgs {
    // No arguments needed - all nodes are pinged
}

impl ToolArguments for ClusterPingArgs {
    const TOOL_NAME: &'static str = "cluster_ping";
}

/// Arguments for the cluster_status tool
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ClusterStatusArgs {
    /// Optional specific node to check (if None, checks all nodes)
    pub node: Option<NodeName>,
}

impl ToolArguments for ClusterStatusArgs {
    const TOOL_NAME: &'static str = "cluster_status";
}

/// Arguments for the service_status tool
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServiceStatusArgs {
    /// The systemd service name to check
    pub service: ServiceName,
    /// Optional specific node to check (if None, checks all nodes)
    pub node: Option<NodeName>,
}

impl ToolArguments for ServiceStatusArgs {
    const TOOL_NAME: &'static str = "service_status";
}

/// Arguments for the resource_usage tool
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ResourceUsageArgs {
    /// Optional specific node to check (if None, checks all nodes)
    pub node: Option<NodeName>,
}

impl ToolArguments for ResourceUsageArgs {
    const TOOL_NAME: &'static str = "resource_usage";
}

/// Arguments for the cluster_info tool
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ClusterInfoArgs {
    // No arguments needed - returns comprehensive cluster information
}

impl ToolArguments for ClusterInfoArgs {
    const TOOL_NAME: &'static str = "cluster_info";
}

/// Arguments for the shell_command tool
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ShellCommandArgs {
    /// The shell command to execute
    pub command: ShellCommand,
    /// Optional specific node to run on (if None, runs on allyrion)
    pub node: Option<NodeName>,
    /// Optional: run as root user
    pub as_root: Option<bool>,
    /// Optional: command timeout in seconds
    pub timeout: Option<u32>,
}

impl ToolArguments for ShellCommandArgs {
    const TOOL_NAME: &'static str = "shell_command";

    fn validate(&self) -> Result<(), ToolArgumentError> {
        self.command.validate()
    }
}

/// Arguments for the journald_logs tool
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JournaldLogsArgs {
    /// Optional specific node to read logs from
    pub node: Option<NodeName>,
    /// Optional systemd service/unit to filter by
    pub service: Option<ServiceName>,
    /// Optional log priority level filter
    pub priority: Option<LogPriority>,
    /// Optional time constraint for log entries
    pub since: Option<String>,
    /// Optional maximum number of log lines to return
    pub lines: Option<u32>,
    /// Optional: follow logs in real-time (not supported in MCP context)
    pub follow: Option<bool>,
}

impl Default for JournaldLogsArgs {
    fn default() -> Self {
        Self {
            node: None,
            service: None,
            priority: None,
            since: None,
            lines: Some(100), // Default limit
            follow: Some(false),
        }
    }
}

impl ToolArguments for JournaldLogsArgs {
    const TOOL_NAME: &'static str = "journald_logs";

    fn validate(&self) -> Result<(), ToolArgumentError> {
        if let Some(follow) = self.follow {
            if follow {
                return Err(ToolArgumentError::DependencyConstraint {
                    reason: "Real-time log following is not supported in MCP context".to_string(),
                });
            }
        }
        Ok(())
    }
}

/// Arguments for the loki_logs tool
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LokiLogsArgs {
    /// LogQL query string
    pub query: LogQLQuery,
    /// Optional start time for log query
    pub start: Option<String>,
    /// Optional end time for log query
    pub end: Option<String>,
    /// Optional maximum number of log entries to return
    pub limit: Option<u32>,
    /// Optional query direction
    pub direction: Option<LogDirection>,
}

impl ToolArguments for LokiLogsArgs {
    const TOOL_NAME: &'static str = "loki_logs";
}

/// Arguments for the screenshot_url tool
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScreenshotUrlArgs {
    /// The URL to capture a screenshot of
    pub url: HttpUrl,
    /// Optional viewport width in pixels
    pub width: Option<u32>,
    /// Optional viewport height in pixels
    pub height: Option<u32>,
    /// Optional CSS selector to wait for before taking screenshot
    pub wait_for_selector: Option<String>,
    /// Optional maximum time to wait for page load in milliseconds
    pub wait_timeout_ms: Option<u32>,
}

impl Default for ScreenshotUrlArgs {
    fn default() -> Self {
        Self {
            url: HttpUrl("https://example.com".to_string()), // This will be overridden
            width: Some(1920),
            height: Some(1080),
            wait_for_selector: None,
            wait_timeout_ms: Some(5000),
        }
    }
}

impl ToolArguments for ScreenshotUrlArgs {
    const TOOL_NAME: &'static str = "screenshot_url";
}

/// Arguments for the screenshot_dashboard tool
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScreenshotDashboardArgs {
    /// The Grafana dashboard URL to capture
    pub dashboard_url: HttpUrl,
}

impl ToolArguments for ScreenshotDashboardArgs {
    const TOOL_NAME: &'static str = "screenshot_dashboard";
}

// === Type-safe wrapper types ===

/// A validated cluster node name
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct NodeName(String);

impl NodeName {
    const VALID_NODES: &'static [&'static str] = &[
        "allyrion",
        "bettley",
        "cargyll",
        "dalt",
        "erenford",
        "fenn",
        "gardener",
        "harlton",
        "inchfield",
        "jast",
        "karstark",
        "lipps",
        "velaryon",
    ];

    /// Create a new NodeName, validating it's a known cluster node
    pub fn new(name: impl Into<String>) -> Result<Self, ToolArgumentError> {
        let name = name.into();
        if Self::VALID_NODES.contains(&name.as_str()) {
            Ok(NodeName(name))
        } else {
            Err(ToolArgumentError::InvalidValue {
                field: "node".to_string(),
                reason: format!(
                    "Unknown node '{name}'. Valid nodes: {}",
                    Self::VALID_NODES.join(", ")
                ),
            })
        }
    }

    /// Get the node name as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get all valid node names
    pub fn valid_nodes() -> &'static [&'static str] {
        Self::VALID_NODES
    }
}

impl std::fmt::Display for NodeName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<NodeName> for String {
    fn from(node: NodeName) -> String {
        node.0
    }
}

/// A validated systemd service name
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ServiceName(String);

impl ServiceName {
    /// Create a new ServiceName with basic validation
    pub fn new(name: impl Into<String>) -> Result<Self, ToolArgumentError> {
        let name = name.into();

        if name.trim().is_empty() {
            return Err(ToolArgumentError::InvalidValue {
                field: "service".to_string(),
                reason: "Service name cannot be empty".to_string(),
            });
        }

        // Basic systemd service name validation
        if name.contains('/') || name.contains('\0') {
            return Err(ToolArgumentError::InvalidValue {
                field: "service".to_string(),
                reason: "Service name contains invalid characters".to_string(),
            });
        }

        Ok(ServiceName(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ServiceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<ServiceName> for String {
    fn from(service: ServiceName) -> String {
        service.0
    }
}

/// A validated shell command with security checks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ShellCommand(String);

impl ShellCommand {
    /// Dangerous command patterns that are blocked
    const DANGEROUS_PATTERNS: &'static [&'static str] = &[
        "rm -rf",
        ">/dev/",
        "mkfs",
        "dd if=",
        ":(){ :|:& };:",
        "curl | sh",
        "wget | sh",
        "chmod +x",
        "> /etc/",
    ];

    /// Create a new ShellCommand with security validation
    pub fn new(command: impl Into<String>) -> Result<Self, ToolArgumentError> {
        let command = command.into();

        if command.trim().is_empty() {
            return Err(ToolArgumentError::InvalidValue {
                field: "command".to_string(),
                reason: "Command cannot be empty".to_string(),
            });
        }

        let cmd = ShellCommand(command);
        cmd.validate()?;
        Ok(cmd)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validate the command for security issues
    pub fn validate(&self) -> Result<(), ToolArgumentError> {
        for pattern in Self::DANGEROUS_PATTERNS {
            if self.0.contains(pattern) {
                return Err(ToolArgumentError::SecurityViolation {
                    reason: format!("potentially dangerous command pattern detected: {pattern}"),
                });
            }
        }
        Ok(())
    }
}

impl std::fmt::Display for ShellCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<ShellCommand> for String {
    fn from(cmd: ShellCommand) -> String {
        cmd.0
    }
}

/// Log priority levels for journald filtering
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LogPriority {
    #[serde(rename = "0")]
    Emergency = 0,
    #[serde(rename = "1")]
    Alert = 1,
    #[serde(rename = "2")]
    Critical = 2,
    #[serde(rename = "3")]
    Error = 3,
    #[serde(rename = "4")]
    Warning = 4,
    #[serde(rename = "5")]
    Notice = 5,
    #[serde(rename = "6")]
    Info = 6,
    #[serde(rename = "7")]
    Debug = 7,
}

impl LogPriority {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogPriority::Emergency => "0",
            LogPriority::Alert => "1",
            LogPriority::Critical => "2",
            LogPriority::Error => "3",
            LogPriority::Warning => "4",
            LogPriority::Notice => "5",
            LogPriority::Info => "6",
            LogPriority::Debug => "7",
        }
    }
}

/// Query direction for Loki logs
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum LogDirection {
    Forward,
    #[default]
    Backward,
}

/// A validated LogQL query string
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogQLQuery(String);

impl LogQLQuery {
    pub fn new(query: impl Into<String>) -> Result<Self, ToolArgumentError> {
        let query = query.into();

        if query.trim().is_empty() {
            return Err(ToolArgumentError::InvalidValue {
                field: "query".to_string(),
                reason: "LogQL query cannot be empty".to_string(),
            });
        }

        // Basic LogQL validation - must start with a label selector
        if !query.trim().starts_with('{') {
            return Err(ToolArgumentError::InvalidValue {
                field: "query".to_string(),
                reason: "LogQL query must start with a label selector (e.g., '{job=\"consul\"}')"
                    .to_string(),
            });
        }

        Ok(LogQLQuery(query))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for LogQLQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<LogQLQuery> for String {
    fn from(query: LogQLQuery) -> String {
        query.0
    }
}

/// A validated HTTP/HTTPS URL
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HttpUrl(String);

impl HttpUrl {
    pub fn new(url: impl Into<String>) -> Result<Self, ToolArgumentError> {
        let url = url.into();

        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(ToolArgumentError::InvalidValue {
                field: "url".to_string(),
                reason: "URL must start with http:// or https://".to_string(),
            });
        }

        Ok(HttpUrl(url))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for HttpUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<HttpUrl> for String {
    fn from(url: HttpUrl) -> String {
        url.0
    }
}

/// Union type for all tool arguments
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "tool_name")]
pub enum ToolArgs {
    #[serde(rename = "cluster_ping")]
    ClusterPing(ClusterPingArgs),
    #[serde(rename = "cluster_status")]
    ClusterStatus(ClusterStatusArgs),
    #[serde(rename = "service_status")]
    ServiceStatus(ServiceStatusArgs),
    #[serde(rename = "resource_usage")]
    ResourceUsage(ResourceUsageArgs),
    #[serde(rename = "cluster_info")]
    ClusterInfo(ClusterInfoArgs),
    #[serde(rename = "shell_command")]
    ShellCommand(ShellCommandArgs),
    #[serde(rename = "journald_logs")]
    JournaldLogs(JournaldLogsArgs),
    #[serde(rename = "loki_logs")]
    LokiLogs(LokiLogsArgs),
    #[serde(rename = "screenshot_url")]
    ScreenshotUrl(ScreenshotUrlArgs),
    #[serde(rename = "screenshot_dashboard")]
    ScreenshotDashboard(ScreenshotDashboardArgs),
}

impl ToolArgs {
    /// Get the tool name for this set of arguments
    pub fn tool_name(&self) -> &'static str {
        match self {
            ToolArgs::ClusterPing(_) => ClusterPingArgs::TOOL_NAME,
            ToolArgs::ClusterStatus(_) => ClusterStatusArgs::TOOL_NAME,
            ToolArgs::ServiceStatus(_) => ServiceStatusArgs::TOOL_NAME,
            ToolArgs::ResourceUsage(_) => ResourceUsageArgs::TOOL_NAME,
            ToolArgs::ClusterInfo(_) => ClusterInfoArgs::TOOL_NAME,
            ToolArgs::ShellCommand(_) => ShellCommandArgs::TOOL_NAME,
            ToolArgs::JournaldLogs(_) => JournaldLogsArgs::TOOL_NAME,
            ToolArgs::LokiLogs(_) => LokiLogsArgs::TOOL_NAME,
            ToolArgs::ScreenshotUrl(_) => ScreenshotUrlArgs::TOOL_NAME,
            ToolArgs::ScreenshotDashboard(_) => ScreenshotDashboardArgs::TOOL_NAME,
        }
    }

    /// Validate the arguments
    pub fn validate(&self) -> Result<(), ToolArgumentError> {
        match self {
            ToolArgs::ClusterPing(args) => args.validate(),
            ToolArgs::ClusterStatus(args) => args.validate(),
            ToolArgs::ServiceStatus(args) => args.validate(),
            ToolArgs::ResourceUsage(args) => args.validate(),
            ToolArgs::ClusterInfo(args) => args.validate(),
            ToolArgs::ShellCommand(args) => args.validate(),
            ToolArgs::JournaldLogs(args) => args.validate(),
            ToolArgs::LokiLogs(args) => args.validate(),
            ToolArgs::ScreenshotUrl(args) => args.validate(),
            ToolArgs::ScreenshotDashboard(args) => args.validate(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_name_validation() {
        // Valid node names
        assert!(NodeName::new("allyrion").is_ok());
        assert!(NodeName::new("velaryon").is_ok());

        // Invalid node names
        assert!(NodeName::new("invalid_node").is_err());
        assert!(NodeName::new("").is_err());
    }

    #[test]
    fn test_shell_command_security() {
        // Safe commands
        assert!(ShellCommand::new("ls -la").is_ok());
        assert!(ShellCommand::new("systemctl status consul").is_ok());

        // Dangerous commands
        assert!(ShellCommand::new("rm -rf /").is_err());
        assert!(ShellCommand::new("dd if=/dev/zero of=/dev/sda").is_err());
        assert!(ShellCommand::new("").is_err());
    }

    #[test]
    fn test_logql_query_validation() {
        // Valid LogQL queries
        assert!(LogQLQuery::new(r#"{job="consul"}"#).is_ok());
        assert!(LogQLQuery::new(r#"{job="consul"} |= "error""#).is_ok());

        // Invalid LogQL queries
        assert!(LogQLQuery::new("invalid query").is_err());
        assert!(LogQLQuery::new("").is_err());
    }

    #[test]
    fn test_http_url_validation() {
        // Valid URLs
        assert!(HttpUrl::new("https://example.com").is_ok());
        assert!(HttpUrl::new("http://localhost:3000").is_ok());

        // Invalid URLs
        assert!(HttpUrl::new("ftp://example.com").is_err());
        assert!(HttpUrl::new("example.com").is_err());
        assert!(HttpUrl::new("").is_err());
    }
}
