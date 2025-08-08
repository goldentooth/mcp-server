//! Type-safe I/O stream separation
//!
//! These types guarantee that MCP messages only go to stdout and logs only
//! go to stderr. It's impossible to accidentally write logs to stdout or
//! MCP messages to stderr.

use crate::types::{LogEntry, McpMessage};
use derivative::Derivative;
use std::io;
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Wrapper around stdout that can only write MCP messages
#[derive(Derivative)]
#[derivative(Debug)]
pub struct StdoutWriter {
    #[derivative(Debug = "ignore")]
    writer: Box<dyn AsyncWrite + Send + Unpin>,
}

impl Default for StdoutWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl StdoutWriter {
    /// Create a new stdout writer for MCP messages
    pub fn new() -> Self {
        Self {
            writer: Box::new(tokio::io::stdout()),
        }
    }

    /// Create a stdout writer for testing with a custom writer
    pub fn new_with_writer<W>(writer: W) -> Self
    where
        W: AsyncWrite + Send + Unpin + 'static,
    {
        Self {
            writer: Box::new(writer),
        }
    }

    /// Write an MCP message to stdout (the only allowed content)
    pub async fn write_mcp_message(&mut self, message: &McpMessage) -> Result<(), io::Error> {
        let json = message
            .to_json_string()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Write JSON + newline (MCP protocol requirement)
        self.writer.write_all(json.as_bytes()).await?;
        self.writer.write_all(b"\n").await?;
        self.writer.flush().await?;

        Ok(())
    }

    /// Flush the writer
    pub async fn flush(&mut self) -> Result<(), io::Error> {
        self.writer.flush().await
    }
}

/// Wrapper around stderr that can only write log entries
#[derive(Derivative)]
#[derivative(Debug)]
pub struct StderrWriter {
    #[derivative(Debug = "ignore")]
    writer: Box<dyn AsyncWrite + Send + Unpin>,
}

impl Default for StderrWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl StderrWriter {
    /// Create a new stderr writer for log entries
    pub fn new() -> Self {
        Self {
            writer: Box::new(tokio::io::stderr()),
        }
    }

    /// Create a stderr writer for testing with a custom writer
    pub fn new_with_writer<W>(writer: W) -> Self
    where
        W: AsyncWrite + Send + Unpin + 'static,
    {
        Self {
            writer: Box::new(writer),
        }
    }

    /// Write a log entry to stderr (the only allowed content)
    pub async fn write_log_entry(&mut self, entry: &LogEntry) -> Result<(), io::Error> {
        let log_line = entry
            .to_json_string()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Write JSON log entry + newline
        self.writer.write_all(log_line.as_bytes()).await?;
        self.writer.write_all(b"\n").await?;
        self.writer.flush().await?;

        Ok(())
    }

    /// Write a simple log message (will be wrapped in LogEntry)
    pub async fn write_log(
        &mut self,
        level: crate::types::LogLevel,
        message: &str,
    ) -> Result<(), io::Error> {
        let entry = LogEntry::new(level, message.to_string());
        self.write_log_entry(&entry).await
    }

    /// Flush the writer
    pub async fn flush(&mut self) -> Result<(), io::Error> {
        self.writer.flush().await
    }
}

/// Combined I/O streams for the MCP server
#[derive(Debug)]
pub struct McpStreams {
    pub stdout: StdoutWriter,
    pub stderr: StderrWriter,
    log_level_threshold: crate::types::LogLevel,
}

impl Default for McpStreams {
    fn default() -> Self {
        Self::new()
    }
}

impl McpStreams {
    /// Create new streams using actual stdout/stderr
    pub fn new() -> Self {
        let log_level = if cfg!(test) {
            // During tests, only log errors to reduce noise
            crate::types::LogLevel::Error
        } else {
            // In production, use environment variable
            crate::types::LogLevel::from_env("MCP_LOG_LEVEL")
        };

        Self {
            stdout: StdoutWriter::new(),
            stderr: StderrWriter::new(),
            log_level_threshold: log_level,
        }
    }

    /// Create new streams with a specific log level threshold
    pub fn new_with_log_level(log_level: crate::types::LogLevel) -> Self {
        Self {
            stdout: StdoutWriter::new(),
            stderr: StderrWriter::new(),
            log_level_threshold: log_level,
        }
    }

    /// Create streams for testing with custom writers
    pub fn new_with_writers<OUT, ERR>(stdout: OUT, stderr: ERR) -> Self
    where
        OUT: AsyncWrite + Send + Unpin + 'static,
        ERR: AsyncWrite + Send + Unpin + 'static,
    {
        Self {
            stdout: StdoutWriter::new_with_writer(stdout),
            stderr: StderrWriter::new_with_writer(stderr),
            log_level_threshold: crate::types::LogLevel::Error, // Only errors during tests
        }
    }

    /// Create streams for testing with custom writers and specific log level
    pub fn new_with_writers_and_log_level<OUT, ERR>(
        stdout: OUT,
        stderr: ERR,
        log_level: crate::types::LogLevel,
    ) -> Self
    where
        OUT: AsyncWrite + Send + Unpin + 'static,
        ERR: AsyncWrite + Send + Unpin + 'static,
    {
        Self {
            stdout: StdoutWriter::new_with_writer(stdout),
            stderr: StderrWriter::new_with_writer(stderr),
            log_level_threshold: log_level,
        }
    }

    /// Send an MCP response (guaranteed to go to stdout)
    pub async fn send_response(&mut self, message: McpMessage) -> Result<(), io::Error> {
        self.stdout.write_mcp_message(&message).await
    }

    /// Write a log message (guaranteed to go to stderr)
    pub async fn log(
        &mut self,
        level: crate::types::LogLevel,
        message: &str,
    ) -> Result<(), io::Error> {
        if level.should_log(self.log_level_threshold) {
            self.stderr.write_log(level, message).await
        } else {
            // Skip logging if below threshold
            Ok(())
        }
    }

    /// Log an info message
    pub async fn log_info(&mut self, message: &str) -> Result<(), io::Error> {
        self.log(crate::types::LogLevel::Info, message).await
    }

    /// Log an error message
    pub async fn log_error(&mut self, message: &str) -> Result<(), io::Error> {
        self.log(crate::types::LogLevel::Error, message).await
    }

    /// Log a debug message
    pub async fn log_debug(&mut self, message: &str) -> Result<(), io::Error> {
        self.log(crate::types::LogLevel::Debug, message).await
    }

    /// Log a trace message
    pub async fn log_trace(&mut self, message: &str) -> Result<(), io::Error> {
        self.log(crate::types::LogLevel::Trace, message).await
    }

    /// Log a warning message
    pub async fn log_warn(&mut self, message: &str) -> Result<(), io::Error> {
        self.log(crate::types::LogLevel::Warn, message).await
    }

    /// Set the log level threshold (useful for testing)
    pub fn set_log_level(&mut self, level: crate::types::LogLevel) {
        self.log_level_threshold = level;
    }

    /// Get the current log level threshold
    pub fn log_level(&self) -> crate::types::LogLevel {
        self.log_level_threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{McpRequest, MessageId};

    #[test]
    fn test_stream_type_safety() {
        // This test demonstrates compile-time guarantees
        // We can only create MCP messages with valid structure
        let message = McpMessage::Request(McpRequest::ping(MessageId::Number(1)));

        // We can only call write_mcp_message with McpMessage
        // We can only call write_log with LogLevel and string

        // These would fail to compile:
        // stdout.write_log(...);     // Wrong stream
        // stderr.write_mcp_message(...); // Wrong stream
        // stdout.write("plain text");     // Wrong content type

        assert_eq!(message.id(), &MessageId::Number(1));
    }

    #[test]
    fn test_mcp_message_serialization() {
        let message = McpMessage::Request(McpRequest::ping(MessageId::Number(1)));
        let json = message.to_json_string().unwrap();

        // Must contain JSON-RPC 2.0 fields
        assert!(json.contains(r#""jsonrpc":"2.0""#));
        assert!(json.contains(r#""method":"ping""#));
        assert!(json.contains(r#""id":1"#));
    }

    #[test]
    fn test_log_entry_serialization() {
        let entry = LogEntry::info("Test message".to_string());
        let json = entry.to_json_string().unwrap();

        // Must contain structured log fields
        assert!(json.contains(r#""level":"info""#));
        assert!(json.contains("Test message"));
        assert!(json.contains("timestamp"));
    }
}
