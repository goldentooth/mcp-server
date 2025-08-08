use goldentooth_mcp::protocol::process_json_request;
use goldentooth_mcp::types::{LogLevel, McpStreams};
use std::env;
use tokio::io::{AsyncBufReadExt, BufReader};

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

/// Handle --version flag with type-safe output
async fn handle_version(streams: &mut McpStreams) -> Result<(), Box<dyn std::error::Error>> {
    // Log the version request (goes to stderr)
    streams.log_debug("Version requested").await?;

    // Create version information
    let git_sha = option_env!("VERGEN_GIT_SHA_SHORT").unwrap_or("unknown");
    let git_branch = option_env!("VERGEN_GIT_BRANCH").unwrap_or("unknown");
    let build_time = option_env!("VERGEN_BUILD_TIMESTAMP").unwrap_or("unknown");

    let version_info = format!(
        "{} {}\nBuilt from commit: {} ({})\nBuild time: {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        git_sha,
        git_branch,
        build_time
    );

    // Version output goes to stdout (but our streams ensure it's not an MCP message)
    // For CLI usage, we need to print directly since we're not in MCP mode
    println!("{version_info}");

    Ok(())
}

/// Handle --help flag with type-safe output
async fn handle_help(streams: &mut McpStreams) -> Result<(), Box<dyn std::error::Error>> {
    streams.log_debug("Help requested").await?;

    let help_text = format!(
        "{} {} - MCP server for Goldentooth cluster management

USAGE:
    {} [OPTIONS]

OPTIONS:
    -h, --help       Print this help message
    -v, --version    Print version information

ENVIRONMENT VARIABLES:
    MCP_LOG_LEVEL    Set logging level (trace, debug, info, warn, error) [default: info]
    MCP_LOCAL        Bind to localhost only when using HTTP transport

The server starts in stdio mode by default for MCP client integration.
All logs are written to stderr, MCP messages to stdout.

Examples:
    {}                    # Start in stdio mode
    MCP_LOG_LEVEL=debug {}  # Start with debug logging
",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_NAME"),
    );

    // Help output goes to stdout for CLI usage
    println!("{help_text}");

    Ok(())
}

/// Handle invalid arguments with type-safe error reporting
async fn handle_invalid_arg(
    streams: &mut McpStreams,
    arg: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Log the error (goes to stderr)
    streams
        .log_error(&format!("Invalid argument: {arg}"))
        .await?;

    let error_msg = format!("Error: Unknown argument '{arg}'\n\nUse --help for usage information.");

    // Error message goes to stderr for CLI usage
    eprintln!("{error_msg}");

    Ok(())
}

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

    while let Some(line) = lines.next_line().await? {
        // Skip empty lines
        if line.trim().is_empty() {
            continue;
        }

        streams.log_trace(&format!("Received line: {line}")).await?;

        // Process the JSON-RPC message using our protocol module
        let response = match process_json_request(&line, streams).await {
            Ok(response) => response,
            Err(e) => {
                streams
                    .log_error(&format!("Failed to process request: {e}"))
                    .await?;
                continue; // Skip this malformed request
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
