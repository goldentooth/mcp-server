//! Log level types with compile-time validation
//!
//! These types ensure that only valid log levels can be constructed,
//! and provide automatic serialization and environment variable parsing.

use serde::{Deserialize, Serialize};
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

/// Log levels in order of severity (lowest to highest)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

impl Display for LogLevel {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let level_str = match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        };
        write!(f, "{level_str}")
    }
}

impl FromStr for LogLevel {
    type Err = InvalidLogLevel;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "trace" => Ok(LogLevel::Trace),
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" | "warning" => Ok(LogLevel::Warn),
            "error" | "err" => Ok(LogLevel::Error),
            _ => Err(InvalidLogLevel(s.to_string())),
        }
    }
}

impl LogLevel {
    /// Parse log level from environment variable, with fallback
    pub fn from_env(var_name: &str) -> Self {
        std::env::var(var_name)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_default()
    }

    /// Check if this level should be logged at the given threshold
    pub fn should_log(&self, threshold: LogLevel) -> bool {
        *self >= threshold
    }

    /// Get all valid log level strings (for help text)
    pub fn valid_values() -> &'static [&'static str] {
        &["trace", "debug", "info", "warn", "error"]
    }
}

/// Error type for invalid log level strings
#[derive(Debug, Clone)]
pub struct InvalidLogLevel(pub String);

impl Display for InvalidLogLevel {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "Invalid log level '{}'. Valid levels are: {}",
            self.0,
            LogLevel::valid_values().join(", ")
        )
    }
}

impl std::error::Error for InvalidLogLevel {}

/// Structured log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: LogLevel,
    pub message: String,
    pub context: Option<serde_json::Value>,
}

impl LogEntry {
    /// Create a new log entry with current timestamp
    pub fn new(level: LogLevel, message: String) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            level,
            message,
            context: None,
        }
    }

    /// Create a log entry with additional context
    pub fn new_with_context(level: LogLevel, message: String, context: serde_json::Value) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            level,
            message,
            context: Some(context),
        }
    }

    /// Serialize to JSON string for output
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Create an error log entry
    pub fn error(message: String) -> Self {
        Self::new(LogLevel::Error, message)
    }

    /// Create a warning log entry
    pub fn warn(message: String) -> Self {
        Self::new(LogLevel::Warn, message)
    }

    /// Create an info log entry
    pub fn info(message: String) -> Self {
        Self::new(LogLevel::Info, message)
    }

    /// Create a debug log entry
    pub fn debug(message: String) -> Self {
        Self::new(LogLevel::Debug, message)
    }

    /// Create a trace log entry
    pub fn trace(message: String) -> Self {
        Self::new(LogLevel::Trace, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_from_str() {
        assert_eq!("trace".parse::<LogLevel>().unwrap(), LogLevel::Trace);
        assert_eq!("debug".parse::<LogLevel>().unwrap(), LogLevel::Debug);
        assert_eq!("info".parse::<LogLevel>().unwrap(), LogLevel::Info);
        assert_eq!("warn".parse::<LogLevel>().unwrap(), LogLevel::Warn);
        assert_eq!("warning".parse::<LogLevel>().unwrap(), LogLevel::Warn);
        assert_eq!("error".parse::<LogLevel>().unwrap(), LogLevel::Error);
        assert_eq!("err".parse::<LogLevel>().unwrap(), LogLevel::Error);

        // Case insensitive
        assert_eq!("INFO".parse::<LogLevel>().unwrap(), LogLevel::Info);
        assert_eq!("Error".parse::<LogLevel>().unwrap(), LogLevel::Error);

        // Invalid
        assert!("invalid".parse::<LogLevel>().is_err());
        assert!("".parse::<LogLevel>().is_err());
    }

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Error > LogLevel::Warn);
        assert!(LogLevel::Warn > LogLevel::Info);
        assert!(LogLevel::Info > LogLevel::Debug);
        assert!(LogLevel::Debug > LogLevel::Trace);
    }

    #[test]
    fn test_should_log() {
        assert!(LogLevel::Error.should_log(LogLevel::Info));
        assert!(LogLevel::Info.should_log(LogLevel::Info));
        assert!(!LogLevel::Debug.should_log(LogLevel::Info));
        assert!(!LogLevel::Trace.should_log(LogLevel::Warn));
    }

    #[test]
    fn test_log_entry_serialization() {
        let entry = LogEntry::info("Test message".to_string());
        let json = entry.to_json_string().unwrap();

        assert!(json.contains(r#""level":"info""#));
        assert!(json.contains("Test message"));
        assert!(json.contains("timestamp"));
    }

    #[test]
    fn test_log_entry_with_context() {
        let context = serde_json::json!({"request_id": 123, "method": "ping"});
        let entry =
            LogEntry::new_with_context(LogLevel::Debug, "Processing request".to_string(), context);

        let json = entry.to_json_string().unwrap();
        assert!(json.contains("request_id"));
        assert!(json.contains("method"));
    }

    #[test]
    fn test_from_env() {
        // Test with valid environment variable
        unsafe {
            std::env::set_var("TEST_LOG_LEVEL", "debug");
        }
        assert_eq!(LogLevel::from_env("TEST_LOG_LEVEL"), LogLevel::Debug);

        // Test with invalid environment variable (should use default)
        unsafe {
            std::env::set_var("TEST_LOG_LEVEL_INVALID", "invalid");
        }
        assert_eq!(LogLevel::from_env("TEST_LOG_LEVEL_INVALID"), LogLevel::Info);

        // Test with missing environment variable (should use default)
        assert_eq!(LogLevel::from_env("NONEXISTENT_VAR"), LogLevel::Info);

        // Clean up
        unsafe {
            std::env::remove_var("TEST_LOG_LEVEL");
            std::env::remove_var("TEST_LOG_LEVEL_INVALID");
        }
    }
}
