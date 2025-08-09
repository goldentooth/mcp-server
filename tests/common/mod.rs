use serde_json::Value;
use std::process::{ExitStatus, Stdio};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};

pub mod test_helpers;

// Re-export commonly used items for convenience
pub use test_helpers::{McpRequestBuilders, McpRequestProcessor};

#[allow(dead_code)]
pub struct McpServerProcess {
    pub child: Child,
    pub stdin: ChildStdin,
    pub stdout: BufReader<ChildStdout>,
    pub stderr: BufReader<ChildStderr>,
}

#[allow(dead_code)]
impl McpServerProcess {
    pub async fn spawn() -> Result<Self, Box<dyn std::error::Error>> {
        // First ensure the binary is built
        let build_result = Command::new("cargo")
            .args(["build"])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .await?;

        if !build_result.status.success() {
            let stderr = String::from_utf8_lossy(&build_result.stderr);
            return Err(format!("Build failed: {stderr}").into());
        }

        let mut child = Command::new("./target/debug/goldentooth-mcp")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let stdin = child.stdin.take().ok_or("Failed to get stdin")?;
        let stdout = BufReader::new(child.stdout.take().ok_or("Failed to get stdout")?);
        let stderr = BufReader::new(child.stderr.take().ok_or("Failed to get stderr")?);

        Ok(McpServerProcess {
            child,
            stdin,
            stdout,
            stderr,
        })
    }

    pub async fn send_mcp_request(
        &mut self,
        request: Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let request_str = serde_json::to_string(&request)?;
        self.stdin.write_all(request_str.as_bytes()).await?;
        self.stdin.write_all(b"\n").await?;
        self.stdin.flush().await?;
        Ok(())
    }

    pub async fn receive_mcp_response(
        &mut self,
    ) -> Result<Option<Value>, Box<dyn std::error::Error>> {
        let mut line = String::new();
        match self.stdout.read_line(&mut line).await? {
            0 => Ok(None), // EOF
            _ => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    Ok(None)
                } else {
                    let response: Value = serde_json::from_str(trimmed)?;
                    Ok(Some(response))
                }
            }
        }
    }

    pub async fn collect_stderr_logs(&mut self) -> Result<String, Box<dyn std::error::Error>> {
        let logs = String::new();
        // Try to read available stderr data without blocking
        while let Ok(line) = tokio::time::timeout(
            tokio::time::Duration::from_millis(100),
            self.stderr.read_line(&mut String::new()),
        )
        .await
        {
            if line? == 0 {
                break;
            } // EOF
        }
        Ok(logs)
    }

    pub async fn shutdown_gracefully(&mut self) -> Result<ExitStatus, Box<dyn std::error::Error>> {
        // Close stdin to signal shutdown
        self.stdin.shutdown().await?;

        // Wait for process to exit
        let status = self.child.wait().await?;
        Ok(status)
    }

    pub async fn kill(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.child.kill().await?;
        Ok(())
    }
}
