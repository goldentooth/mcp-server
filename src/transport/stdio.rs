//! Stdio Transport Implementation
//!
//! Standard input/output transport for MCP server.
//! Processes newline-delimited JSON-RPC messages from stdin and sends responses to stdout.

use crate::protocol::process_json_request;
use crate::types::{LogLevel, McpError, McpMessage, McpStreams, MessageId};
use tokio::io::{AsyncBufReadExt, BufReader};

/// Stdio Transport server for MCP
pub struct StdioTransport {
    log_level: LogLevel,
}

impl StdioTransport {
    /// Create a new Stdio transport
    pub fn new(log_level: LogLevel) -> Self {
        Self { log_level }
    }

    /// Start the stdio transport server
    pub async fn start(&self, streams: &mut McpStreams) -> Result<(), Box<dyn std::error::Error>> {
        // Log server startup
        streams.log_info("Starting in stdio mode").await?;
        streams
            .log_debug(&format!("Log level set to: {}", self.log_level))
            .await?;

        // Start the MCP message processing loop
        streams.log_info("MCP server ready for requests").await?;

        self.run_server_loop(streams).await?;

        Ok(())
    }

    /// Main MCP server loop that processes JSON-RPC messages from stdin
    async fn run_server_loop(
        &self,
        streams: &mut McpStreams,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let stdin = tokio::io::stdin();
        let reader = BufReader::new(stdin);
        let mut lines = reader.lines();

        streams
            .log_debug("Starting message processing loop")
            .await?;

        let mut consecutive_errors = 0;
        const MAX_CONSECUTIVE_ERRORS: usize = 5;

        while let Some(line) = lines.next_line().await? {
            // Skip empty lines
            if line.trim().is_empty() {
                continue;
            }

            streams.log_trace(&format!("Received line: {line}")).await?;

            // Process the JSON-RPC message using our protocol module
            let response = match process_json_request(&line, streams).await {
                Ok(response) => {
                    // Reset error count on successful processing
                    consecutive_errors = 0;
                    response
                }
                Err(e) => {
                    consecutive_errors += 1;
                    streams
                        .log_error(&format!(
                            "Failed to process request ({consecutive_errors}/{MAX_CONSECUTIVE_ERRORS}): {e}"
                        ))
                        .await?;

                    if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                        streams
                            .log_error(
                                "Too many consecutive errors, shutting down to prevent infinite loop",
                            )
                            .await?;
                        return Err(format!(
                            "Exceeded maximum consecutive errors ({MAX_CONSECUTIVE_ERRORS})"
                        )
                        .into());
                    }

                    // Try to create a parse error response if we can extract an ID
                    // Otherwise skip this request
                    if let Ok(parsed_json) = serde_json::from_str::<serde_json::Value>(&line) {
                        if let Some(id_value) = parsed_json.get("id") {
                            // Try to create a proper error response with the original ID
                            let id = if let Some(num) = id_value.as_u64() {
                                MessageId::Number(num)
                            } else if let Some(s) = id_value.as_str() {
                                MessageId::String(s.to_string())
                            } else {
                                MessageId::Number(0)
                            };
                            McpMessage::Error(McpError::invalid_request(
                                id,
                                Some(serde_json::json!({"error": "Request processing failed"})),
                            ))
                        } else {
                            // No ID found, skip this request
                            continue;
                        }
                    } else {
                        // Completely invalid JSON, skip
                        continue;
                    }
                }
            };

            // Send response to stdout using our type-safe streams
            if let Err(e) = streams.send_response(response).await {
                streams
                    .log_error(&format!("Failed to send response: {e}"))
                    .await?;
                break;
            }
        }

        streams.log_info("MCP server shutting down").await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stdio_transport_creation() {
        let transport = StdioTransport::new(LogLevel::Info);
        assert_eq!(transport.log_level, LogLevel::Info);
    }

    #[tokio::test]
    async fn test_stdio_transport_with_debug_level() {
        let transport = StdioTransport::new(LogLevel::Debug);
        assert_eq!(transport.log_level, LogLevel::Debug);
    }
}
