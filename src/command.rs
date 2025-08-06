use async_trait::async_trait;
use std::collections::HashMap;
use std::process::Command as StdCommand;
use std::sync::{Arc, Mutex};

/// Trait for executing system commands
#[async_trait]
pub trait CommandExecutor: Send + Sync {
    /// Execute a command with given arguments
    async fn execute(&self, command: &str, args: &[&str]) -> Result<String, String>;
}

/// System command executor that runs actual commands
pub struct SystemCommandExecutor;

impl SystemCommandExecutor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SystemCommandExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CommandExecutor for SystemCommandExecutor {
    async fn execute(&self, command: &str, args: &[&str]) -> Result<String, String> {
        let output = StdCommand::new(command)
            .args(args)
            .output()
            .map_err(|e| format!("Failed to execute command: {e}"))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            Err(format!(
                "Command failed with status {}: {}",
                output.status.code().unwrap_or(-1),
                stderr
            ))
        }
    }
}

type ExecutionHistory = Arc<Mutex<Vec<(String, Vec<String>)>>>;

/// Mock command executor for testing
pub struct MockCommandExecutor {
    responses: HashMap<String, Result<String, String>>,
    execution_history: ExecutionHistory,
}

impl MockCommandExecutor {
    pub fn new() -> Self {
        Self {
            responses: HashMap::new(),
            execution_history: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn with_response(
        mut self,
        command: &str,
        args: &[&str],
        response: Result<String, String>,
    ) -> Self {
        let key = format!("{} {}", command, args.join(" "));
        self.responses.insert(key, response);
        self
    }

    pub fn get_execution_history(&self) -> Vec<(String, Vec<String>)> {
        self.execution_history.lock().unwrap().clone()
    }
}

impl Default for MockCommandExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CommandExecutor for MockCommandExecutor {
    async fn execute(&self, command: &str, args: &[&str]) -> Result<String, String> {
        let key = format!("{} {}", command, args.join(" "));

        // Track execution
        self.execution_history.lock().unwrap().push((
            command.to_string(),
            args.iter().map(|s| s.to_string()).collect(),
        ));

        self.responses
            .get(&key)
            .cloned()
            .unwrap_or_else(|| Err(format!("No mock response for: {key}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_system_executor_executes_echo() {
        let executor = SystemCommandExecutor::new();
        let result = executor.execute("echo", &["hello"]).await;
        assert_eq!(result, Ok("hello\n".to_string()));
    }

    #[tokio::test]
    async fn test_system_executor_handles_failure() {
        let executor = SystemCommandExecutor::new();
        let result = executor.execute("false", &[]).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Command failed"));
    }

    #[tokio::test]
    async fn test_mock_executor_returns_configured_responses() {
        let executor = MockCommandExecutor::new()
            .with_response(
                "goldentooth",
                &["ping", "all"],
                Ok("All nodes online".to_string()),
            )
            .with_response(
                "goldentooth",
                &["status"],
                Err("Command failed".to_string()),
            );

        let result = executor.execute("goldentooth", &["ping", "all"]).await;
        assert_eq!(result, Ok("All nodes online".to_string()));

        let result = executor.execute("goldentooth", &["status"]).await;
        assert_eq!(result, Err("Command failed".to_string()));
    }

    #[tokio::test]
    async fn test_mock_executor_tracks_execution_history() {
        let executor = MockCommandExecutor::new().with_response(
            "goldentooth",
            &["ping", "all"],
            Ok("OK".to_string()),
        );

        executor
            .execute("goldentooth", &["ping", "all"])
            .await
            .unwrap();
        executor
            .execute("goldentooth", &["status", "node1"])
            .await
            .ok();

        let history = executor.get_execution_history();
        assert_eq!(history.len(), 2);
        assert_eq!(
            history[0],
            (
                "goldentooth".to_string(),
                vec!["ping".to_string(), "all".to_string()]
            )
        );
        assert_eq!(
            history[1],
            (
                "goldentooth".to_string(),
                vec!["status".to_string(), "node1".to_string()]
            )
        );
    }
}
