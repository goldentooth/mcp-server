use rmcp::ServiceExt;
use tokio::io::{stdin, stdout};

use goldentooth_mcp::service::GoldentoothService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let transport = (stdin(), stdout());

    let service = GoldentoothService::new();

    let server = service.serve(transport).await?;

    let _quit_reason = server.waiting().await?;

    Ok(())
}
