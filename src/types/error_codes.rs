//! JSON-RPC error codes with compile-time validation
//!
//! These types ensure that only standard JSON-RPC error codes can be used,
//! preventing invalid error responses and ensuring spec compliance.

use serde::{Deserialize, Serialize};
use std::fmt::{self, Display, Formatter};

/// Standard JSON-RPC 2.0 error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JsonRpcErrorCode {
    /// Invalid JSON was received by the server
    ParseError = -32700,
    /// The JSON sent is not a valid Request object
    InvalidRequest = -32600,
    /// The method does not exist / is not available
    MethodNotFound = -32601,
    /// Invalid method parameter(s)
    InvalidParams = -32602,
    /// Internal JSON-RPC error
    InternalError = -32603,
}

impl JsonRpcErrorCode {
    /// Get the standard error message for this code
    pub fn message(&self) -> &'static str {
        match self {
            JsonRpcErrorCode::ParseError => "Parse error",
            JsonRpcErrorCode::InvalidRequest => "Invalid Request",
            JsonRpcErrorCode::InvalidParams => "Invalid params",
            JsonRpcErrorCode::MethodNotFound => "Method not found",
            JsonRpcErrorCode::InternalError => "Internal error",
        }
    }

    /// Get the numeric error code
    pub fn code(&self) -> i32 {
        *self as i32
    }

    /// Create from numeric code (returns None for invalid codes)
    pub fn from_code(code: i32) -> Option<Self> {
        match code {
            -32700 => Some(JsonRpcErrorCode::ParseError),
            -32600 => Some(JsonRpcErrorCode::InvalidRequest),
            -32601 => Some(JsonRpcErrorCode::MethodNotFound),
            -32602 => Some(JsonRpcErrorCode::InvalidParams),
            -32603 => Some(JsonRpcErrorCode::InternalError),
            _ => None,
        }
    }

    /// Get all valid error codes (for documentation/testing)
    pub fn all_codes() -> &'static [JsonRpcErrorCode] {
        &[
            JsonRpcErrorCode::ParseError,
            JsonRpcErrorCode::InvalidRequest,
            JsonRpcErrorCode::MethodNotFound,
            JsonRpcErrorCode::InvalidParams,
            JsonRpcErrorCode::InternalError,
        ]
    }
}

impl Display for JsonRpcErrorCode {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{} ({})", self.message(), self.code())
    }
}

/// Application-specific error codes (following JSON-RPC spec for custom codes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum McpErrorCode {
    /// Cluster node is unreachable
    NodeUnreachable = -32000,
    /// Authentication failed
    AuthenticationFailed = -32001,
    /// Tool execution failed
    ToolExecutionFailed = -32002,
    /// Configuration error
    ConfigurationError = -32003,
    /// Resource temporarily unavailable
    ResourceUnavailable = -32004,
    /// Operation timed out
    OperationTimeout = -32005,
}

impl McpErrorCode {
    /// Get the error message for this MCP-specific code
    pub fn message(&self) -> &'static str {
        match self {
            McpErrorCode::NodeUnreachable => "Cluster node is unreachable",
            McpErrorCode::AuthenticationFailed => "Authentication failed",
            McpErrorCode::ToolExecutionFailed => "Tool execution failed",
            McpErrorCode::ConfigurationError => "Configuration error",
            McpErrorCode::ResourceUnavailable => "Resource temporarily unavailable",
            McpErrorCode::OperationTimeout => "Operation timed out",
        }
    }

    /// Get the numeric error code
    pub fn code(&self) -> i32 {
        *self as i32
    }

    /// Create from numeric code (returns None for invalid codes)
    pub fn from_code(code: i32) -> Option<Self> {
        match code {
            -32000 => Some(McpErrorCode::NodeUnreachable),
            -32001 => Some(McpErrorCode::AuthenticationFailed),
            -32002 => Some(McpErrorCode::ToolExecutionFailed),
            -32003 => Some(McpErrorCode::ConfigurationError),
            -32004 => Some(McpErrorCode::ResourceUnavailable),
            -32005 => Some(McpErrorCode::OperationTimeout),
            _ => None,
        }
    }
}

impl Display for McpErrorCode {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{} ({})", self.message(), self.code())
    }
}

/// Unified error code type that covers both JSON-RPC and MCP-specific errors
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ErrorCode {
    JsonRpc(JsonRpcErrorCode),
    Mcp(McpErrorCode),
}

impl ErrorCode {
    /// Get the numeric error code
    pub fn code(&self) -> i32 {
        match self {
            ErrorCode::JsonRpc(code) => code.code(),
            ErrorCode::Mcp(code) => code.code(),
        }
    }

    /// Get the error message
    pub fn message(&self) -> &'static str {
        match self {
            ErrorCode::JsonRpc(code) => code.message(),
            ErrorCode::Mcp(code) => code.message(),
        }
    }

    /// Create from numeric code (checks both JSON-RPC and MCP codes)
    pub fn from_code(code: i32) -> Option<Self> {
        if let Some(json_rpc) = JsonRpcErrorCode::from_code(code) {
            Some(ErrorCode::JsonRpc(json_rpc))
        } else {
            McpErrorCode::from_code(code).map(ErrorCode::Mcp)
        }
    }

    /// Check if this is a JSON-RPC standard error
    pub fn is_json_rpc_standard(&self) -> bool {
        matches!(self, ErrorCode::JsonRpc(_))
    }

    /// Check if this is an MCP-specific error
    pub fn is_mcp_specific(&self) -> bool {
        matches!(self, ErrorCode::Mcp(_))
    }
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            ErrorCode::JsonRpc(code) => code.fmt(f),
            ErrorCode::Mcp(code) => code.fmt(f),
        }
    }
}

impl From<JsonRpcErrorCode> for ErrorCode {
    fn from(code: JsonRpcErrorCode) -> Self {
        ErrorCode::JsonRpc(code)
    }
}

impl From<McpErrorCode> for ErrorCode {
    fn from(code: McpErrorCode) -> Self {
        ErrorCode::Mcp(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_rpc_error_codes() {
        assert_eq!(JsonRpcErrorCode::ParseError.code(), -32700);
        assert_eq!(JsonRpcErrorCode::ParseError.message(), "Parse error");

        assert_eq!(JsonRpcErrorCode::MethodNotFound.code(), -32601);
        assert_eq!(
            JsonRpcErrorCode::MethodNotFound.message(),
            "Method not found"
        );
    }

    #[test]
    fn test_mcp_error_codes() {
        assert_eq!(McpErrorCode::NodeUnreachable.code(), -32000);
        assert_eq!(
            McpErrorCode::NodeUnreachable.message(),
            "Cluster node is unreachable"
        );

        assert_eq!(McpErrorCode::ToolExecutionFailed.code(), -32002);
        assert_eq!(
            McpErrorCode::ToolExecutionFailed.message(),
            "Tool execution failed"
        );
    }

    #[test]
    fn test_error_code_from_numeric() {
        assert_eq!(
            JsonRpcErrorCode::from_code(-32601),
            Some(JsonRpcErrorCode::MethodNotFound)
        );

        assert_eq!(
            McpErrorCode::from_code(-32000),
            Some(McpErrorCode::NodeUnreachable)
        );

        assert_eq!(JsonRpcErrorCode::from_code(-99999), None);
        assert_eq!(McpErrorCode::from_code(-99999), None);
    }

    #[test]
    fn test_unified_error_code() {
        let json_rpc_err = ErrorCode::JsonRpc(JsonRpcErrorCode::ParseError);
        assert_eq!(json_rpc_err.code(), -32700);
        assert!(json_rpc_err.is_json_rpc_standard());
        assert!(!json_rpc_err.is_mcp_specific());

        let mcp_err = ErrorCode::Mcp(McpErrorCode::NodeUnreachable);
        assert_eq!(mcp_err.code(), -32000);
        assert!(!mcp_err.is_json_rpc_standard());
        assert!(mcp_err.is_mcp_specific());
    }

    #[test]
    fn test_error_code_conversion() {
        let json_rpc = JsonRpcErrorCode::InvalidRequest;
        let unified: ErrorCode = json_rpc.into();
        assert_eq!(unified.code(), -32600);

        let mcp = McpErrorCode::AuthenticationFailed;
        let unified: ErrorCode = mcp.into();
        assert_eq!(unified.code(), -32001);
    }

    #[test]
    fn test_unified_from_code() {
        // Should find JSON-RPC codes
        assert_eq!(
            ErrorCode::from_code(-32700),
            Some(ErrorCode::JsonRpc(JsonRpcErrorCode::ParseError))
        );

        // Should find MCP codes
        assert_eq!(
            ErrorCode::from_code(-32000),
            Some(ErrorCode::Mcp(McpErrorCode::NodeUnreachable))
        );

        // Should return None for unknown codes
        assert_eq!(ErrorCode::from_code(-99999), None);
    }

    #[test]
    fn test_display_formatting() {
        let json_rpc = JsonRpcErrorCode::MethodNotFound;
        assert_eq!(format!("{json_rpc}"), "Method not found (-32601)");

        let mcp = McpErrorCode::NodeUnreachable;
        assert_eq!(format!("{mcp}"), "Cluster node is unreachable (-32000)");
    }
}
