use goldentooth_mcp::http_server::HttpServer;
use goldentooth_mcp::service::GoldentoothService;
use serde_json::Value;

#[tokio::main]
async fn main() {
    println!("Testing fixed protocol version in HTTP responses:");

    let service = GoldentoothService::new();
    let server = HttpServer::new(service, None);

    // Test the initialize request
    let request = r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}},"id":1}"#;
    let response = server
        .handle_request_for_test("initialize", request, None)
        .await
        .unwrap();

    println!("Initialize response:");
    println!("{}", response);

    // Parse and verify the response
    let json: Value = serde_json::from_str(&response).unwrap();
    let protocol_version = json["result"]["protocolVersion"].as_str().unwrap();
    println!("\nProtocol version returned: {}", protocol_version);

    // Verify it's not the old hardcoded "0.1.0"
    assert_ne!(protocol_version, "0.1.0");
    assert_eq!(protocol_version, "2024-11-05");

    println!(
        "✅ Protocol version is now correctly set to: {}",
        protocol_version
    );
    println!("✅ Fixed: Server no longer hardcodes '0.1.0' version!");
}
