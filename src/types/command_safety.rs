//! Compile-time command safety mechanisms
//!
//! This module provides type-safe wrappers and compile-time guarantees for safe
//! command execution. It uses phantom types and trait bounds to prevent dangerous
//! operations from being compiled.

use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

/// Safety level markers for commands
pub mod safety_levels {
    /// Commands that are completely safe and cannot cause system damage
    #[derive(Debug)]
    pub struct Safe;

    /// Commands that require elevated privileges but are controlled
    #[derive(Debug)]
    pub struct Privileged;

    /// Commands that can modify system state but are validated
    #[derive(Debug)]
    pub struct SystemModifying;

    /// Commands that are inherently dangerous and require explicit approval
    #[derive(Debug)]
    pub struct Dangerous;

    /// Commands that are completely forbidden
    #[derive(Debug)]
    pub struct Forbidden;
}

/// Type-safe command wrapper with safety guarantees
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeCommand<S> {
    command: String,
    _safety_level: PhantomData<S>,
}

/// Trait for commands that can be executed
pub trait Executable {}

/// Safe commands can always be executed
impl Executable for SafeCommand<safety_levels::Safe> {}

/// Privileged commands can be executed with proper authorization
impl Executable for SafeCommand<safety_levels::Privileged> {}

/// System modifying commands can be executed with validation
impl Executable for SafeCommand<safety_levels::SystemModifying> {}

// Dangerous and Forbidden commands do NOT implement Executable

/// Command safety analyzer
pub struct CommandSafetyAnalyzer;

impl CommandSafetyAnalyzer {
    /// Analyze a command and return the safest possible wrapper
    pub fn analyze(command: &str) -> CommandAnalysisResult {
        let trimmed = command.trim();

        if trimmed.is_empty() {
            return CommandAnalysisResult::Forbidden("Empty command".to_string());
        }

        // Check for explicitly forbidden patterns
        if Self::is_forbidden(trimmed) {
            return CommandAnalysisResult::Forbidden(
                "Command contains forbidden patterns".to_string(),
            );
        }

        // Check for dangerous patterns
        if Self::is_dangerous(trimmed) {
            return CommandAnalysisResult::Dangerous(
                "Command contains potentially dangerous operations".to_string(),
            );
        }

        // Check for system modifying operations
        if Self::is_system_modifying(trimmed) {
            return CommandAnalysisResult::SystemModifying(SafeCommand {
                command: command.to_string(),
                _safety_level: PhantomData,
            });
        }

        // Check for privileged operations
        if Self::is_privileged(trimmed) {
            return CommandAnalysisResult::Privileged(SafeCommand {
                command: command.to_string(),
                _safety_level: PhantomData,
            });
        }

        // Default to safe
        CommandAnalysisResult::Safe(SafeCommand {
            command: command.to_string(),
            _safety_level: PhantomData,
        })
    }

    /// Check if command contains forbidden patterns
    fn is_forbidden(command: &str) -> bool {
        // These patterns are absolutely forbidden and should never be executed

        // Check for exact root filesystem deletion
        if command == "rm -rf /" || command.starts_with("rm -rf / ") {
            return true;
        }

        const FORBIDDEN_PATTERNS: &[&str] = &[
            "dd if=/dev/zero",
            "mkfs",
            "fdisk",
            "parted",
            ":(){ :|:& };:", // Fork bomb
            "curl | sh",
            "wget | sh",
            "bash <(curl",
            "bash <(wget",
            "shutdown -h now",
            "init 0",
            "halt",
            "reboot",
            "systemctl poweroff",
            "systemctl halt",
            "systemctl reboot",
        ];

        FORBIDDEN_PATTERNS
            .iter()
            .any(|pattern| command.contains(pattern))
    }

    /// Check if command contains dangerous patterns
    fn is_dangerous(command: &str) -> bool {
        const DANGEROUS_PATTERNS: &[&str] = &[
            "rm -rf",
            "rm -fr",
            "rm -r",
            "> /dev/",
            "dd if=",
            "dd of=",
            "chmod 777",
            "chmod -R 777",
            "chown -R",
            "usermod",
            "userdel",
            "passwd",
            "su -",
            "sudo su",
            "exec(",
            "eval(",
            "system(",
        ];

        DANGEROUS_PATTERNS
            .iter()
            .any(|pattern| command.contains(pattern))
    }

    /// Check if command modifies system state
    fn is_system_modifying(command: &str) -> bool {
        const SYSTEM_MODIFYING_PATTERNS: &[&str] = &[
            "systemctl start",
            "systemctl stop",
            "systemctl restart",
            "systemctl reload",
            "systemctl enable",
            "systemctl disable",
            "service ",
            "mount ",
            "umount ",
            "iptables",
            "ufw ",
            "firewall-cmd",
            "crontab -e",
            "echo ", // Could write to files
            "tee ",  // Writes to files
            "apt install",
            "apt remove",
            "yum install",
            "yum remove",
            "pacman -S",
            "pacman -R",
            "mkdir",
            "rmdir",
            "touch",
            "cp ",
            "mv ",
            "ln ",
        ];

        // Check if it starts with any system modifying command
        SYSTEM_MODIFYING_PATTERNS.iter().any(|pattern| {
            command.starts_with(pattern)
                || command.starts_with(&format!("sudo {pattern}"))
                || command.contains(&format!(" && {pattern}"))
                || command.contains(&format!("; {pattern}"))
        })
    }

    /// Check if command requires elevated privileges
    fn is_privileged(command: &str) -> bool {
        const PRIVILEGED_PATTERNS: &[&str] = &[
            "sudo ",
            "su -c",
            "journalctl",
            "systemctl status",
            "systemctl list-units",
            "systemctl is-active",
            "systemctl is-enabled",
            "dmesg",
            "netstat -",
            "ss -",
            "lsof",
            "ps aux",
        ];

        // Check for direct pattern matches
        let direct_match = PRIVILEGED_PATTERNS.iter().any(|pattern| {
            command.starts_with(pattern) || command.contains(&format!(" {pattern}"))
        });

        // Check for /var/log access patterns
        let log_access = command.contains("/var/log/")
            && (command.starts_with("tail ")
                || command.starts_with("cat ")
                || command.starts_with("grep ")
                || command.starts_with("less ")
                || command.starts_with("more "));

        direct_match || log_access
    }
}

/// Result of command safety analysis
#[derive(Debug)]
pub enum CommandAnalysisResult {
    Safe(SafeCommand<safety_levels::Safe>),
    Privileged(SafeCommand<safety_levels::Privileged>),
    SystemModifying(SafeCommand<safety_levels::SystemModifying>),
    Dangerous(String), // Reason why it's dangerous
    Forbidden(String), // Reason why it's forbidden
}

impl CommandAnalysisResult {
    /// Check if the command can be executed
    pub fn is_executable(&self) -> bool {
        matches!(
            self,
            CommandAnalysisResult::Safe(_)
                | CommandAnalysisResult::Privileged(_)
                | CommandAnalysisResult::SystemModifying(_)
        )
    }

    /// Get the reason if command cannot be executed
    pub fn rejection_reason(&self) -> Option<&str> {
        match self {
            CommandAnalysisResult::Dangerous(reason) => Some(reason),
            CommandAnalysisResult::Forbidden(reason) => Some(reason),
            _ => None,
        }
    }

    /// Extract the command if it's executable
    pub fn into_command(self) -> Result<String, String> {
        match self {
            CommandAnalysisResult::Safe(cmd) => Ok(cmd.command),
            CommandAnalysisResult::Privileged(cmd) => Ok(cmd.command),
            CommandAnalysisResult::SystemModifying(cmd) => Ok(cmd.command),
            CommandAnalysisResult::Dangerous(reason) => Err(reason),
            CommandAnalysisResult::Forbidden(reason) => Err(reason),
        }
    }
}

/// Execution context for commands
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// Whether the execution context has root privileges
    pub has_root: bool,
    /// Whether system modifications are allowed
    pub allow_system_modifications: bool,
    /// Maximum execution timeout in seconds
    pub max_timeout: u32,
    /// Environment restrictions
    pub restricted_environment: bool,
}

impl Default for ExecutionContext {
    fn default() -> Self {
        Self {
            has_root: false,
            allow_system_modifications: false,
            max_timeout: 30,
            restricted_environment: true,
        }
    }
}

impl ExecutionContext {
    /// Create a context for safe operations only
    pub fn safe_only() -> Self {
        Self {
            has_root: false,
            allow_system_modifications: false,
            max_timeout: 15,
            restricted_environment: true,
        }
    }

    /// Create a context for privileged operations
    pub fn privileged(has_root: bool) -> Self {
        Self {
            has_root,
            allow_system_modifications: false,
            max_timeout: 60,
            restricted_environment: true,
        }
    }

    /// Create a context that allows system modifications
    pub fn system_admin(has_root: bool) -> Self {
        Self {
            has_root,
            allow_system_modifications: true,
            max_timeout: 300,
            restricted_environment: false,
        }
    }

    /// Check if a command can be executed in this context
    pub fn can_execute<S>(&self, _command: &SafeCommand<S>) -> Result<(), ExecutionError>
    where
        SafeCommand<S>: Executable,
    {
        Ok(()) // If it compiles, safe commands can always execute
    }

    /// Check if a privileged command can be executed
    pub fn can_execute_privileged(
        &self,
        _command: &SafeCommand<safety_levels::Privileged>,
    ) -> Result<(), ExecutionError> {
        if !self.has_root {
            return Err(ExecutionError::InsufficientPrivileges {
                required: "root access".to_string(),
            });
        }
        Ok(())
    }

    /// Check if a system modifying command can be executed
    pub fn can_execute_system_modifying(
        &self,
        _command: &SafeCommand<safety_levels::SystemModifying>,
    ) -> Result<(), ExecutionError> {
        if !self.allow_system_modifications {
            return Err(ExecutionError::OperationNotAllowed {
                reason: "System modifications are not allowed in this context".to_string(),
            });
        }
        Ok(())
    }
}

/// Execution errors
#[derive(Debug, Clone, PartialEq)]
pub enum ExecutionError {
    /// Insufficient privileges for command
    InsufficientPrivileges { required: String },
    /// Operation not allowed in current context
    OperationNotAllowed { reason: String },
    /// Command violates security policy
    SecurityPolicyViolation { reason: String },
    /// Timeout constraint violation
    TimeoutExceeded { max_allowed: u32, requested: u32 },
}

impl std::fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutionError::InsufficientPrivileges { required } => {
                write!(f, "Insufficient privileges: {required} required")
            }
            ExecutionError::OperationNotAllowed { reason } => {
                write!(f, "Operation not allowed: {reason}")
            }
            ExecutionError::SecurityPolicyViolation { reason } => {
                write!(f, "Security policy violation: {reason}")
            }
            ExecutionError::TimeoutExceeded {
                max_allowed,
                requested,
            } => {
                write!(
                    f,
                    "Timeout exceeded: requested {requested}s, max allowed {max_allowed}s"
                )
            }
        }
    }
}

impl std::error::Error for ExecutionError {}

/// Node-specific command restrictions
#[derive(Debug, Clone)]
pub struct NodeRestrictions {
    /// Commands that are specifically forbidden on this node
    pub forbidden_commands: Vec<String>,
    /// Whether this node allows destructive operations
    pub allow_destructive: bool,
    /// Maximum resource usage allowed
    pub max_cpu_percent: Option<u32>,
    pub max_memory_mb: Option<u32>,
}

impl Default for NodeRestrictions {
    fn default() -> Self {
        Self {
            forbidden_commands: vec![
                "reboot".to_string(),
                "shutdown".to_string(),
                "halt".to_string(),
            ],
            allow_destructive: false,
            max_cpu_percent: Some(80),
            max_memory_mb: Some(512),
        }
    }
}

impl NodeRestrictions {
    /// Create restrictions for production nodes
    pub fn production() -> Self {
        Self {
            forbidden_commands: vec![
                "reboot".to_string(),
                "shutdown".to_string(),
                "halt".to_string(),
                "systemctl stop".to_string(),
                "systemctl disable".to_string(),
                "rm -rf".to_string(),
            ],
            allow_destructive: false,
            max_cpu_percent: Some(60),
            max_memory_mb: Some(256),
        }
    }

    /// Create restrictions for development/test nodes
    pub fn development() -> Self {
        Self {
            forbidden_commands: vec!["rm -rf /".to_string(), "mkfs".to_string()],
            allow_destructive: true,
            max_cpu_percent: Some(90),
            max_memory_mb: Some(1024),
        }
    }

    /// Check if a command is allowed on this node
    pub fn is_command_allowed(&self, command: &str) -> bool {
        !self
            .forbidden_commands
            .iter()
            .any(|forbidden| command.contains(forbidden))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_command_analysis() {
        // Safe commands
        let result = CommandSafetyAnalyzer::analyze("ls -la");
        assert!(matches!(result, CommandAnalysisResult::Safe(_)));
        assert!(result.is_executable());

        let result = CommandSafetyAnalyzer::analyze("cat /etc/hostname");
        assert!(matches!(result, CommandAnalysisResult::Safe(_)));

        let result = CommandSafetyAnalyzer::analyze("grep error /var/log/syslog");
        assert!(matches!(result, CommandAnalysisResult::Privileged(_)));
    }

    #[test]
    fn test_dangerous_command_detection() {
        let result = CommandSafetyAnalyzer::analyze("rm -rf /");
        assert!(matches!(result, CommandAnalysisResult::Forbidden(_)));
        assert!(!result.is_executable());

        let result = CommandSafetyAnalyzer::analyze("dd if=/dev/zero of=/dev/sda");
        assert!(matches!(result, CommandAnalysisResult::Forbidden(_)));

        let result = CommandSafetyAnalyzer::analyze("rm -rf /tmp/something");
        assert!(matches!(result, CommandAnalysisResult::Dangerous(_)));
    }

    #[test]
    fn test_system_modifying_commands() {
        let result = CommandSafetyAnalyzer::analyze("systemctl restart nginx");
        assert!(matches!(result, CommandAnalysisResult::SystemModifying(_)));
        assert!(result.is_executable());

        let result = CommandSafetyAnalyzer::analyze("mkdir /tmp/test");
        assert!(matches!(result, CommandAnalysisResult::SystemModifying(_)));
    }

    #[test]
    fn test_privileged_commands() {
        let result = CommandSafetyAnalyzer::analyze("journalctl -u consul");
        assert!(matches!(result, CommandAnalysisResult::Privileged(_)));
        assert!(result.is_executable());

        let result = CommandSafetyAnalyzer::analyze("systemctl status consul");
        assert!(matches!(result, CommandAnalysisResult::Privileged(_)));
    }

    #[test]
    fn test_execution_context_validation() {
        let safe_context = ExecutionContext::safe_only();
        let privileged_context = ExecutionContext::privileged(true);

        // Safe commands should work in any context
        if let CommandAnalysisResult::Safe(cmd) = CommandSafetyAnalyzer::analyze("ls -la") {
            assert!(safe_context.can_execute(&cmd).is_ok());
            assert!(privileged_context.can_execute(&cmd).is_ok());
        }

        // Privileged commands need root context
        if let CommandAnalysisResult::Privileged(cmd) = CommandSafetyAnalyzer::analyze("journalctl")
        {
            assert!(safe_context.can_execute_privileged(&cmd).is_err());
            assert!(privileged_context.can_execute_privileged(&cmd).is_ok());
        }
    }

    #[test]
    fn test_node_restrictions() {
        let prod_restrictions = NodeRestrictions::production();

        assert!(!prod_restrictions.is_command_allowed("reboot"));
        assert!(!prod_restrictions.is_command_allowed("systemctl stop consul"));
        assert!(prod_restrictions.is_command_allowed("systemctl status consul"));

        let dev_restrictions = NodeRestrictions::development();
        assert!(dev_restrictions.is_command_allowed("systemctl stop consul"));
        assert!(!dev_restrictions.is_command_allowed("rm -rf /"));
    }

    #[test]
    fn test_empty_command_handling() {
        let result = CommandSafetyAnalyzer::analyze("");
        assert!(matches!(result, CommandAnalysisResult::Forbidden(_)));
        assert!(!result.is_executable());

        let result = CommandSafetyAnalyzer::analyze("   ");
        assert!(matches!(result, CommandAnalysisResult::Forbidden(_)));
    }
}
