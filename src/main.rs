use rmcp::ServiceExt;
use std::env;
use tokio::io::{stdin, stdout};

use goldentooth_mcp::http_server::HttpServer;
use goldentooth_mcp::service::GoldentoothService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize service and auth
    let (service, auth_service) = if env::var("OAUTH_CLIENT_SECRET").is_ok() {
        // Authentication is configured, initialize with auth
        match GoldentoothService::with_auth().await {
            Ok((service, auth)) => {
                println!("MCP server initialized with Authelia authentication");
                (service, Some(auth))
            }
            Err(e) => {
                eprintln!("Failed to initialize authentication: {e}");
                eprintln!("Falling back to no authentication mode");
                (GoldentoothService::new(), None)
            }
        }
    } else {
        println!(
            "MCP server initialized without authentication (set OAUTH_CLIENT_SECRET to enable)"
        );
        (GoldentoothService::new(), None)
    };

    // Initialize screenshot HTTP server
    if let Err(e) = service.initialize_http_server().await {
        eprintln!("Failed to initialize screenshot HTTP server: {e}");
        eprintln!("Screenshots will still work but won't be served via HTTP");
    } else {
        let port = std::env::var("SCREENSHOT_HTTP_PORT").unwrap_or_else(|_| "8081".to_string());
        println!("Screenshot HTTP server initialized on port {port}");
    }

    // Check for HTTP mode via environment variable or command line arg
    if env::var("MCP_HTTP_MODE").is_ok() || env::args().any(|arg| arg == "--http") {
        // HTTP server mode
        let port = env::var("MCP_PORT").unwrap_or_else(|_| "8080".to_string());
        let addr = format!("0.0.0.0:{port}").parse()?;

        let http_server = HttpServer::new(service, auth_service);
        http_server.serve(addr).await?;
    } else {
        // Original stdin/stdout mode
        let transport = (stdin(), stdout());
        let server = service.serve(transport).await?;
        let _quit_reason = server.waiting().await?;
    }

    Ok(())
}
