use rmcp::model::{Implementation, InitializeResult, ProtocolVersion, ServerCapabilities};

fn main() {
    println!("Testing ProtocolVersion override approaches:");

    // Try different ways to create or modify ProtocolVersion

    // Check if ProtocolVersion has any other constructors
    let default_version = ProtocolVersion::V_2024_11_05;
    println!("Default version: {default_version:?}");

    // Try to manually construct InitializeResult with different values
    let custom_init_result = InitializeResult {
        protocol_version: default_version.clone(),
        capabilities: ServerCapabilities::default(),
        server_info: Implementation {
            name: "goldentooth-mcp".to_string(),
            version: "0.0.23".to_string(),
        },
        instructions: None,
    };

    println!("Custom init result:");
    match serde_json::to_string_pretty(&custom_init_result) {
        Ok(json) => println!("{json}"),
        Err(e) => println!("Failed to serialize: {e}"),
    }

    // Check what happens if we try to parse a different version string
    println!("\nTrying to understand ProtocolVersion structure...");

    // See if we can access the inner value
    let version_debug = format!("{default_version:?}");
    println!("Version debug format: {version_debug}");
}
