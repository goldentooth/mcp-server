pub mod auth;
pub mod cluster;
pub mod error;
pub mod logging;
pub mod mcp;
pub mod protocol;
pub mod tools;
pub mod transport;
pub mod types;

pub mod main_functions {
    use crate::types::McpStreams;
    use std::env;

    pub async fn handle_version(
        streams: &mut McpStreams,
    ) -> Result<(), Box<dyn std::error::Error>> {
        streams.log_debug("Version requested").await?;

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

        println!("{version_info}");
        Ok(())
    }

    pub async fn handle_help(streams: &mut McpStreams) -> Result<(), Box<dyn std::error::Error>> {
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

        println!("{help_text}");
        Ok(())
    }

    pub async fn handle_invalid_arg(
        streams: &mut McpStreams,
        arg: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        streams
            .log_error(&format!("Invalid argument: {arg}"))
            .await?;

        let error_msg =
            format!("Error: Unknown argument '{arg}'\n\nUse --help for usage information.");
        eprintln!("{error_msg}");
        Ok(())
    }
}
