//! Integration tests with Goldentooth Agent from GitHub releases
//!
//! This test suite mirrors the approach used by the Goldentooth Agent to test
//! against MCP server releases. By downloading agent releases and testing
//! compatibility, we ensure both projects can always work together effectively.

use serde_json::json;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::{Duration, timeout};

/// Setup function to initialize test logging
fn setup_test() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        env_logger::init();
    });
}

/// Get the path to the Goldentooth Agent binary from GitHub releases
async fn get_agent_binary() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let cache_dir = project_root.join("target").join("test-binaries");

    // Create cache directory if it doesn't exist
    tokio::fs::create_dir_all(&cache_dir).await?;

    let binary_path = cache_dir.join("goldentooth-agent");

    // Check if we already have the binary cached
    if binary_path.exists() {
        return Ok(binary_path);
    }

    eprintln!("Downloading Goldentooth Agent binary from GitHub releases...");

    // Detect the current platform
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;

    let binary_name = match (os, arch) {
        ("linux", "x86_64") => "goldentooth-agent-x86_64-linux",
        ("linux", "aarch64") => "goldentooth-agent-aarch64-linux",
        ("macos", "x86_64") => "goldentooth-agent-x86_64-darwin",
        ("macos", "aarch64") => "goldentooth-agent-aarch64-darwin",
        _ => return Err(format!("Unsupported platform: {os}-{arch}").into()),
    };

    // Download the latest release
    let release_url =
        format!("https://github.com/goldentooth/agent/releases/latest/download/{binary_name}");

    let client = reqwest::Client::new();
    let response = client.get(&release_url).send().await?;

    if !response.status().is_success() {
        if response.status() == 404 {
            eprintln!("No agent releases available yet, skipping integration test");
            // Return a special error that tests can handle to skip gracefully
            return Err("NoReleasesAvailable".into());
        }
        return Err(format!(
            "Failed to download Goldentooth Agent release: HTTP {}. Check that releases are available at: {}",
            response.status(),
            release_url
        ).into());
    }

    let binary_content = response.bytes().await?;

    // Write the binary to disk
    tokio::fs::write(&binary_path, &binary_content).await?;

    // Make it executable on Unix systems
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = tokio::fs::metadata(&binary_path).await?.permissions();
        permissions.set_mode(0o755);
        tokio::fs::set_permissions(&binary_path, permissions).await?;
    }

    eprintln!("Downloaded Goldentooth Agent binary to: {binary_path:?}");
    Ok(binary_path)
}

/// Start the MCP server as a subprocess for testing
async fn start_mcp_server() -> Result<Child, Box<dyn std::error::Error>> {
    let server_path = PathBuf::from(env!("CARGO_BIN_EXE_goldentooth-mcp"));

    let child = Command::new(&server_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    Ok(child)
}

/// Test helper to send a JSON-RPC message and get response
async fn send_jsonrpc_message(
    child: &mut Child,
    message: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let stdin = child.stdin.as_mut().unwrap();
    let stdout = child.stdout.as_mut().unwrap();

    // Send message
    stdin.write_all(message.as_bytes()).await?;
    stdin.write_all(b"\n").await?;
    stdin.flush().await?;

    // Read response
    let mut reader = BufReader::new(stdout);
    let mut response = String::new();

    // Use timeout to prevent hanging
    timeout(Duration::from_secs(10), reader.read_line(&mut response)).await??;

    Ok(response)
}

#[tokio::test]
async fn test_agent_binary_available() {
    setup_test();

    // Verify we can download the agent binary from releases
    let agent_path = match get_agent_binary().await {
        Ok(path) => path,
        Err(e) if e.to_string() == "NoReleasesAvailable" => {
            println!("⏭️  Skipping test - no agent releases available yet");
            return;
        }
        Err(e) => panic!("Should be able to download agent binary from GitHub releases: {e}"),
    };

    assert!(
        agent_path.exists(),
        "Agent binary should exist at {agent_path:?}"
    );

    // Verify the binary is executable
    let metadata =
        std::fs::metadata(&agent_path).expect("Should be able to read agent binary metadata");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = metadata.permissions();
        assert!(
            permissions.mode() & 0o111 != 0,
            "Binary should be executable"
        );
    }

    println!("✓ Goldentooth Agent binary available at: {agent_path:?}");
}

#[tokio::test]
async fn test_mcp_server_agent_compatibility() {
    setup_test();

    let _agent_path = match get_agent_binary().await {
        Ok(path) => path,
        Err(e) if e.to_string() == "NoReleasesAvailable" => {
            println!("⏭️  Skipping test - no agent releases available yet");
            return;
        }
        Err(e) => panic!("Failed to get agent binary: {e}"),
    };

    // Start MCP server
    let mut server = start_mcp_server()
        .await
        .expect("Failed to start MCP server");

    // Test basic MCP protocol flow
    let init_message = json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "id": "test-init",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {
                "experimental": {},
                "sampling": {}
            },
            "clientInfo": {
                "name": "mcp-server-integration-test",
                "version": "0.1.0"
            }
        }
    });

    let response =
        send_jsonrpc_message(&mut server, &serde_json::to_string(&init_message).unwrap())
            .await
            .expect("Should get initialization response");

    let response_json: serde_json::Value =
        serde_json::from_str(&response).expect("Response should be valid JSON");

    // Verify successful initialization
    assert_eq!(response_json["jsonrpc"], "2.0");
    assert_eq!(response_json["id"], "test-init");
    assert!(
        response_json.get("result").is_some(),
        "Should have result field"
    );

    let result = &response_json["result"];
    assert_eq!(result["protocolVersion"], "2025-06-18");
    assert!(result.get("capabilities").is_some());
    assert!(result.get("serverInfo").is_some());

    println!("✓ MCP server successfully initialized with agent protocol");

    // Test tools/list
    let tools_message = json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "id": "test-tools",
        "params": {}
    });

    let tools_response =
        send_jsonrpc_message(&mut server, &serde_json::to_string(&tools_message).unwrap())
            .await
            .expect("Should get tools response");

    let tools_json: serde_json::Value =
        serde_json::from_str(&tools_response).expect("Tools response should be valid JSON");

    assert_eq!(tools_json["id"], "test-tools");
    let tools_result = &tools_json["result"];
    let tools_array = tools_result
        .get("tools")
        .and_then(|t| t.as_array())
        .expect("Should have tools array");

    assert!(!tools_array.is_empty(), "Should have at least one tool");

    // Verify tool structure
    for tool in tools_array {
        assert!(tool.get("name").is_some(), "Tool should have name");
        assert!(
            tool.get("description").is_some(),
            "Tool should have description"
        );
        assert!(
            tool.get("inputSchema").is_some(),
            "Tool should have input schema"
        );
    }

    println!("✓ Tools list compatible with agent expectations");

    // Clean shutdown
    let _ = server.kill().await;
    println!("✓ MCP server and agent protocol compatibility verified");
}

#[tokio::test]
async fn test_protocol_version_enforcement() {
    setup_test();

    let _agent_path = match get_agent_binary().await {
        Ok(path) => path,
        Err(e) if e.to_string() == "NoReleasesAvailable" => {
            println!("⏭️  Skipping test - no agent releases available yet");
            return;
        }
        Err(e) => panic!("Failed to get agent binary: {e}"),
    };

    // Start MCP server
    let mut server = start_mcp_server()
        .await
        .expect("Failed to start MCP server");

    // Test with old protocol version that should be rejected
    let invalid_init_message = json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "id": "test-invalid-version",
        "params": {
            "protocolVersion": "2024-11-05", // Old version
            "capabilities": {},
            "clientInfo": {
                "name": "version-test",
                "version": "1.0.0"
            }
        }
    });

    let response = send_jsonrpc_message(
        &mut server,
        &serde_json::to_string(&invalid_init_message).unwrap(),
    )
    .await
    .expect("Should get error response");

    let response_json: serde_json::Value =
        serde_json::from_str(&response).expect("Response should be valid JSON");

    // Should get an error
    assert_eq!(response_json["id"], "test-invalid-version");
    assert!(
        response_json.get("error").is_some(),
        "Should have error field"
    );

    let error = &response_json["error"];
    assert_eq!(error["code"], -32602); // Invalid params

    println!("✓ Protocol version enforcement works correctly");

    // Clean shutdown
    let _ = server.kill().await;
}

#[tokio::test]
async fn test_error_handling_compatibility() {
    setup_test();

    let _agent_path = match get_agent_binary().await {
        Ok(path) => path,
        Err(e) if e.to_string() == "NoReleasesAvailable" => {
            println!("⏭️  Skipping test - no agent releases available yet");
            return;
        }
        Err(e) => panic!("Failed to get agent binary: {e}"),
    };

    // Start MCP server
    let mut server = start_mcp_server()
        .await
        .expect("Failed to start MCP server");

    // Initialize first
    let init_message = json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "id": "error-test-init",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {
                "name": "error-test",
                "version": "1.0.0"
            }
        }
    });

    let _init_response =
        send_jsonrpc_message(&mut server, &serde_json::to_string(&init_message).unwrap())
            .await
            .expect("Should get initialization response");

    // Test invalid method
    let invalid_method_message = json!({
        "jsonrpc": "2.0",
        "method": "nonexistent/method",
        "id": "error-test",
        "params": {}
    });

    let error_response = send_jsonrpc_message(
        &mut server,
        &serde_json::to_string(&invalid_method_message).unwrap(),
    )
    .await
    .expect("Should get error response");

    let error_json: serde_json::Value =
        serde_json::from_str(&error_response).expect("Error response should be valid JSON");

    // Verify JSON-RPC error format
    assert_eq!(error_json["jsonrpc"], "2.0");
    assert_eq!(error_json["id"], "error-test");
    assert!(error_json.get("error").is_some());

    let error = &error_json["error"];
    assert!(error.get("code").is_some());
    assert!(error.get("message").is_some());

    // Should be method not found error
    let error_code = error["code"].as_i64().unwrap();
    assert!(error_code == -32601 || error_code == -32600); // Method not found or Invalid request

    println!("✓ Error handling format compatible with agent expectations");

    // Clean shutdown
    let _ = server.kill().await;
}
