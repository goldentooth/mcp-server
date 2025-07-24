use rmcp::ServiceExt;
use std::env;
use tokio::io::{stdin, stdout};
use tokio::net::TcpListener;

use goldentooth_mcp::service::GoldentoothService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize service with or without authentication
    let service = if env::var("OAUTH_CLIENT_SECRET").is_ok() {
        // Authentication is configured, initialize with auth
        match GoldentoothService::with_auth().await {
            Ok(service) => {
                println!("MCP server initialized with Authelia authentication");
                service
            }
            Err(e) => {
                eprintln!("Failed to initialize authentication: {}", e);
                eprintln!("Falling back to no authentication mode");
                GoldentoothService::new()
            }
        }
    } else {
        println!(
            "MCP server initialized without authentication (set OAUTH_CLIENT_SECRET to enable)"
        );
        GoldentoothService::new()
    };

    // Check for HTTP mode via environment variable or command line arg
    if env::var("MCP_HTTP_MODE").is_ok() || env::args().any(|arg| arg == "--http") {
        // HTTP server mode
        let port = env::var("MCP_PORT").unwrap_or_else(|_| "8080".to_string());
        let addr = format!("0.0.0.0:{}", port);

        println!("Starting MCP server in HTTP mode on {}", addr);

        let listener = TcpListener::bind(&addr).await?;

        loop {
            let (stream, _) = listener.accept().await?;
            let service = service.clone();

            tokio::spawn(async move {
                let (read, write) = stream.into_split();
                let transport = (read, write);

                if let Ok(server) = service.serve(transport).await {
                    let _ = server.waiting().await;
                }
            });
        }
    } else {
        // Original stdin/stdout mode
        let transport = (stdin(), stdout());
        let server = service.serve(transport).await?;
        let _quit_reason = server.waiting().await?;
    }

    Ok(())
}
