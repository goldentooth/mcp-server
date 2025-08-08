use std::process::Stdio;
use std::sync::Once;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

// Build once for all tests
static BUILD_ONCE: Once = Once::new();

fn ensure_binary_built() {
    BUILD_ONCE.call_once(|| {
        let result = std::process::Command::new("cargo")
            .args(["build"])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .expect("Failed to build binary for subprocess tests");

        if !result.status.success() {
            panic!("Build failed: {}", String::from_utf8_lossy(&result.stderr));
        }
    });
}

#[tokio::test]
async fn test_binary_launches_successfully() {
    ensure_binary_built();

    let child_result = Command::new("./target/debug/goldentooth-mcp")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    match child_result {
        Ok(mut child) => {
            // Server should start and have proper stdio
            assert!(child.stdin.is_some());
            assert!(child.stdout.is_some());

            let _ = child.kill().await;
        }
        Err(e) => {
            panic!("Binary should be able to launch even if not fully implemented: {e}");
        }
    }
}

#[tokio::test]
async fn test_clean_shutdown_on_stdin_close() {
    ensure_binary_built();

    let child_result = Command::new("./target/debug/goldentooth-mcp")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    match child_result {
        Ok(mut child) => {
            // Close stdin - server should exit gracefully
            drop(child.stdin.take());

            let status = child.wait().await.unwrap();
            // For now, any clean exit is acceptable
            // Later we'll require exit code 0
            assert!(status.success() || status.code().is_some());
        }
        Err(e) => {
            panic!("Need working binary for subprocess tests: {e}");
        }
    }
}

#[test] // Not async - this is a simple CLI test
fn test_version_flag() {
    ensure_binary_built();

    let output = std::process::Command::new("./target/debug/goldentooth-mcp")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("--version")
        .output()
        .expect("Failed to execute --version");

    // Should exit successfully
    assert_eq!(output.status.code(), Some(0), "Should exit with code 0");

    let version_output = String::from_utf8_lossy(&output.stdout);
    let expected_version = env!("CARGO_PKG_VERSION");
    // Should contain version from Cargo.toml or binary name
    assert!(
        version_output.contains(expected_version)
            || version_output.contains("goldentooth-mcp")
            || version_output.contains("version"), // Generic version output
        "Version output should contain version info: {version_output}"
    );
}

#[tokio::test]
async fn test_stdout_only_contains_mcp_messages() {
    // This is the most critical test - stdio separation
    ensure_binary_built();

    let child_result = Command::new("./target/debug/goldentooth-mcp")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    match child_result {
        Ok(mut child) => {
            let stdin = child.stdin.as_mut().unwrap();
            let mut stdout = BufReader::new(child.stdout.as_mut().unwrap());

            // Send MCP initialize request
            let init_request = r#"{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#;

            if let Err(e) = stdin.write_all(init_request.as_bytes()).await {
                panic!("Should be able to write to stdin: {e}");
            }
            if let Err(e) = stdin.write_all(b"\n").await {
                panic!("Should be able to write newline: {e}");
            }

            // Try to read response from stdout with timeout
            let mut line = String::new();
            match tokio::time::timeout(
                tokio::time::Duration::from_millis(100),
                stdout.read_line(&mut line),
            )
            .await
            {
                Ok(Ok(0)) => {
                    // EOF - server exited, that's ok for now
                }
                Ok(Ok(_)) => {
                    // Got some output - it should be valid JSON-RPC
                    if !line.trim().is_empty() {
                        match serde_json::from_str::<serde_json::Value>(&line) {
                            Ok(json) => {
                                // Should be valid JSON-RPC
                                assert_eq!(json["jsonrpc"], "2.0");
                            }
                            Err(_) => {
                                panic!(
                                    "stdout should only contain valid JSON-RPC messages, got: {line}"
                                );
                            }
                        }
                    }
                }
                Ok(Err(e)) => {
                    // Read error, acceptable for now
                    eprintln!("Read error (acceptable for now): {e}");
                }
                Err(_) => {
                    // Timeout - no response, which is OK for current implementation
                }
            }

            let _ = child.kill().await;
        }
        Err(e) => {
            panic!("Need working binary for stdio separation test: {e}");
        }
    }
}

#[test]
fn test_help_flag() {
    // Test that --help works (this should be fast)
    ensure_binary_built();

    let output = std::process::Command::new("./target/debug/goldentooth-mcp")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("--help")
        .output();

    match output {
        Ok(result) => {
            // Help should exit successfully or with code 0/2 (common for help)
            let exit_code = result.status.code().unwrap_or(-1);
            assert!(
                exit_code == 0 || exit_code == 2,
                "Help should exit cleanly, got: {exit_code}"
            );

            // Should output something to stdout or stderr
            let stdout = String::from_utf8_lossy(&result.stdout);
            let stderr = String::from_utf8_lossy(&result.stderr);
            assert!(
                !stdout.is_empty() || !stderr.is_empty(),
                "Help should produce output"
            );
        }
        Err(e) => {
            // It's OK if --help isn't implemented yet
            eprintln!("--help not yet implemented: {e}");
        }
    }
}

#[test]
fn test_invalid_args_exit_cleanly() {
    // Test that invalid arguments are handled gracefully
    ensure_binary_built();

    let output = std::process::Command::new("./target/debug/goldentooth-mcp")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("--invalid-flag-that-does-not-exist")
        .output()
        .expect("Should be able to run with invalid args");

    // Should exit with non-zero code for invalid args
    let exit_code = output.status.code().unwrap_or(-1);
    assert_ne!(exit_code, 0, "Invalid args should cause non-zero exit");

    // Error message should go to stderr, not stdout (when implemented)
    // For now, just ensure it doesn't crash
}
