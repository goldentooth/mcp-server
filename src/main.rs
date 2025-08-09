use goldentooth_mcp::main_functions::{handle_help, handle_invalid_arg, handle_version};
use goldentooth_mcp::protocol::process_json_request;
use goldentooth_mcp::transport::HttpTransport;
use goldentooth_mcp::types::{LogLevel, McpStreams};
use std::env;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();

    // Initialize type-safe I/O streams
    let mut streams = McpStreams::new();

    // Set up logging level from environment
    let log_level = LogLevel::from_env("MCP_LOG_LEVEL");

    // Handle command line arguments
    if args.len() > 1 {
        match args[1].as_str() {
            "--version" | "-v" => {
                handle_version(&mut streams).await?;
                return Ok(());
            }
            "--help" | "-h" => {
                handle_help(&mut streams).await?;
                return Ok(());
            }
            "--http" => {
                // HTTP transport mode
                return run_http_transport(&mut streams, log_level).await;
            }
            arg if arg.starts_with("--") => {
                handle_invalid_arg(&mut streams, arg).await?;
                std::process::exit(1);
            }
            _ => {
                handle_invalid_arg(&mut streams, &args[1]).await?;
                std::process::exit(1);
            }
        }
    }

    // Log server startup (goes to stderr automatically)
    streams.log_info("Goldentooth MCP server starting").await?;
    streams
        .log_debug(&format!("Log level set to: {log_level}"))
        .await?;

    // Start MCP server with stdio transport
    streams.log_info("Starting in stdio mode").await?;

    // Start the MCP message processing loop
    streams.log_info("MCP server ready for requests").await?;

    run_mcp_server_loop(&mut streams, log_level).await?;

    Ok(())
}

// Argument handlers moved to lib.rs main_functions module to eliminate duplication

/// Main MCP server loop that processes JSON-RPC messages from stdin
async fn run_mcp_server_loop(
    streams: &mut McpStreams,
    _log_level: LogLevel,
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
                        use goldentooth_mcp::types::{McpError, McpMessage, MessageId};
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

/// Run HTTP transport mode
async fn run_http_transport(
    streams: &mut McpStreams,
    _log_level: LogLevel,
) -> Result<(), Box<dyn std::error::Error>> {
    // Check if we should require authentication
    let auth_required = env::var("MCP_AUTH_REQUIRED")
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(true); // Default to requiring auth

    streams.log_info("Starting HTTP transport mode").await?;

    if auth_required {
        streams
            .log_info("Authentication required for HTTP connections")
            .await?;
    } else {
        streams
            .log_warn(
                "Running HTTP transport WITHOUT authentication (not recommended for production)",
            )
            .await?;
    }

    // Create and start HTTP transport
    let transport = HttpTransport::new(auth_required);
    let addr = transport
        .start()
        .await
        .map_err(|e| format!("Failed to start HTTP transport: {e}"))?;

    streams
        .log_info(&format!("HTTP transport listening on http://{addr}"))
        .await?;
    streams
        .log_info("MCP HTTP server ready for requests")
        .await?;

    // Wait for shutdown signal
    #[cfg(unix)]
    {
        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
        let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())?;

        tokio::select! {
            _ = sigterm.recv() => {
                streams.log_info("Received SIGTERM, shutting down gracefully").await?;
            }
            _ = sigint.recv() => {
                streams.log_info("Received SIGINT, shutting down gracefully").await?;
            }
        }
    }

    #[cfg(not(unix))]
    {
        signal::ctrl_c().await?;
        streams
            .log_info("Received Ctrl+C, shutting down gracefully")
            .await?;
    }

    streams.log_info("HTTP transport shutting down").await?;
    Ok(())
}
