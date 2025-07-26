use rmcp::model::ErrorData;
use thiserror::Error;

/// Unified error type for the MCP server
#[derive(Debug, Error)]
pub enum McpServerError {
    #[error("Command execution failed: {0}")]
    Command(String),

    #[error("Cluster operation failed: {0}")]
    Cluster(#[from] crate::cluster::ClusterOperationError),

    #[error("Authentication failed: {0}")]
    Auth(#[from] crate::auth::AuthError),

    #[error("JSON serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Network request failed: {0}")]
    Network(#[from] reqwest::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Internal server error: {0}")]
    Internal(String),
}

impl McpServerError {
    /// Convert to MCP ErrorData for protocol responses
    pub fn to_error_data(&self) -> ErrorData {
        use rmcp::model::ErrorCode;

        match self {
            McpServerError::Command(msg) => ErrorData {
                code: ErrorCode(-32001),
                message: format!("Command execution failed: {}", msg).into(),
                data: Some(serde_json::json!({
                    "error_type": "command_execution",
                    "details": msg
                })),
            },
            McpServerError::Cluster(err) => ErrorData {
                code: ErrorCode(-32002),
                message: format!("Cluster operation failed: {}", err).into(),
                data: Some(serde_json::json!({
                    "error_type": "cluster_operation",
                    "details": err.to_string()
                })),
            },
            McpServerError::Auth(err) => ErrorData {
                code: ErrorCode(-32003),
                message: format!("Authentication failed: {}", err).into(),
                data: Some(serde_json::json!({
                    "error_type": "authentication",
                    "details": err.to_string()
                })),
            },
            McpServerError::Serialization(err) => ErrorData {
                code: ErrorCode(-32004),
                message: format!("JSON serialization failed: {}", err).into(),
                data: Some(serde_json::json!({
                    "error_type": "serialization",
                    "details": err.to_string()
                })),
            },
            McpServerError::Network(err) => ErrorData {
                code: ErrorCode(-32005),
                message: format!("Network request failed: {}", err).into(),
                data: Some(serde_json::json!({
                    "error_type": "network",
                    "details": err.to_string()
                })),
            },
            McpServerError::Config(msg) => ErrorData {
                code: ErrorCode(-32006),
                message: format!("Configuration error: {}", msg).into(),
                data: Some(serde_json::json!({
                    "error_type": "configuration",
                    "details": msg
                })),
            },
            McpServerError::Internal(msg) => ErrorData {
                code: ErrorCode(-32000),
                message: format!("Internal server error: {}", msg).into(),
                data: Some(serde_json::json!({
                    "error_type": "internal",
                    "details": msg
                })),
            },
        }
    }
}

/// Result type for MCP server operations
pub type McpResult<T> = Result<T, McpServerError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_to_error_data_conversion() {
        let error = McpServerError::Command("timeout".to_string());
        let error_data = error.to_error_data();

        assert_eq!(error_data.code.0, -32001);
        assert!(error_data.message.contains("Command execution failed"));
        assert!(error_data.message.contains("timeout"));

        let data = error_data.data.unwrap();
        assert_eq!(data["error_type"], "command_execution");
        assert_eq!(data["details"], "timeout");
    }

    #[test]
    fn test_cluster_error_conversion() {
        let cluster_err =
            crate::cluster::ClusterOperationError::CommandFailed("network error".to_string());
        let error = McpServerError::Cluster(cluster_err);
        let error_data = error.to_error_data();

        assert_eq!(error_data.code.0, -32002);
        assert!(error_data.message.contains("Cluster operation failed"));

        let data = error_data.data.unwrap();
        assert_eq!(data["error_type"], "cluster_operation");
    }

    #[test]
    fn test_auth_error_conversion() {
        let auth_err = crate::auth::AuthError::InvalidConfig("missing secret".to_string());
        let error = McpServerError::Auth(auth_err);
        let error_data = error.to_error_data();

        assert_eq!(error_data.code.0, -32003);
        assert!(error_data.message.contains("Authentication failed"));

        let data = error_data.data.unwrap();
        assert_eq!(data["error_type"], "authentication");
    }

    #[test]
    fn test_serialization_error_conversion() {
        // Create a mock serialization error
        let serde_error = serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::Other,
            "test serialization error",
        ));
        let error = McpServerError::Serialization(serde_error);
        let error_data = error.to_error_data();

        assert_eq!(error_data.code.0, -32004);
        assert!(error_data.message.contains("JSON serialization failed"));

        let data = error_data.data.unwrap();
        assert_eq!(data["error_type"], "serialization");
    }

    #[test]
    fn test_config_error_conversion() {
        let error = McpServerError::Config("invalid port".to_string());
        let error_data = error.to_error_data();

        assert_eq!(error_data.code.0, -32006);
        assert!(error_data.message.contains("Configuration error"));

        let data = error_data.data.unwrap();
        assert_eq!(data["error_type"], "configuration");
        assert_eq!(data["details"], "invalid port");
    }

    #[test]
    fn test_internal_error_conversion() {
        let error = McpServerError::Internal("unexpected state".to_string());
        let error_data = error.to_error_data();

        assert_eq!(error_data.code.0, -32000);
        assert!(error_data.message.contains("Internal server error"));

        let data = error_data.data.unwrap();
        assert_eq!(data["error_type"], "internal");
        assert_eq!(data["details"], "unexpected state");
    }
}
