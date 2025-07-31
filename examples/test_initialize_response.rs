use goldentooth_mcp::service::GoldentoothService;
use rmcp::Service;

#[tokio::main]
async fn main() {
    println!("Testing MCP initialize response:");

    let service = GoldentoothService::new();
    let info = service.get_info();

    println!("Server info returned by get_info():");
    println!("  Protocol version: {:?}", info.protocol_version);
    println!("  Server name: {}", info.server_info.name);
    println!("  Server version: {}", info.server_info.version);
    println!("  Instructions: {:?}", info.instructions);

    // Try to serialize this to JSON to see what it looks like
    match serde_json::to_string_pretty(&info) {
        Ok(json) => {
            println!("\nSerialized to JSON:");
            println!("{}", json);
        }
        Err(e) => {
            println!("Failed to serialize: {}", e);
        }
    }
}
