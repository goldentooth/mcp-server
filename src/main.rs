use goldentooth_mcp::main_functions::{handle_help, handle_invalid_arg, handle_version};
use goldentooth_mcp::transport::{HttpTransport, StdioTransport};
use goldentooth_mcp::types::{LogLevel, McpStreams};
use std::env;
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

    // Start MCP server with stdio transport
    let transport = StdioTransport::new(log_level);
    transport.start(&mut streams).await?;

    Ok(())
}

// Argument handlers moved to lib.rs main_functions module to eliminate duplication

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
