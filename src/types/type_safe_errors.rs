//! Type-safe error handling system
//!
//! This module provides a comprehensive type-safe error handling system that
//! replaces runtime validation errors with compile-time safety. It uses phantom
//! types and the type system to ensure proper error handling and propagation.

use crate::types::{MessageId, ProtocolComplianceError, ToolArgumentError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::marker::PhantomData;

/// Error context markers for type safety
pub mod error_contexts {
    /// Errors that occur during protocol parsing
    #[derive(Debug)]
    pub struct Protocol;

    /// Errors that occur during tool execution
    #[derive(Debug)]
    pub struct Tool;

    /// Errors that occur during argument validation
    #[derive(Debug)]
    pub struct Argument;

    /// Errors that occur during command execution
    #[derive(Debug)]
    pub struct Command;

    /// Errors that occur during authentication
    #[derive(Debug)]
    pub struct Authentication;

    /// Errors that occur during transport operations
    #[derive(Debug)]
    pub struct Transport;
}

/// Type-safe error wrapper
#[derive(Debug, Clone)]
pub struct TypeSafeError<Context> {
    /// The underlying error information
    error: ErrorInfo,
    /// Phantom marker for compile-time context checking
    _context: PhantomData<Context>,
}

/// Core error information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorInfo {
    /// Error code for programmatic handling
    pub code: i32,
    /// Human-readable error message
    pub message: String,
    /// Optional structured data for error details
    pub data: Option<Value>,
    /// Optional cause chain for error tracing
    pub cause: Option<Box<ErrorInfo>>,
    /// Request ID this error is associated with
    pub request_id: Option<MessageId>,
}

impl<Context> TypeSafeError<Context> {
    /// Create a new typed error
    pub fn new(code: i32, message: String, data: Option<Value>) -> Self {
        Self {
            error: ErrorInfo {
                code,
                message,
                data,
                cause: None,
                request_id: None,
            },
            _context: PhantomData,
        }
    }

    /// Create a typed error with a request ID
    pub fn with_request_id(mut self, request_id: MessageId) -> Self {
        self.error.request_id = Some(request_id);
        self
    }

    /// Add a cause to this error
    pub fn with_cause(mut self, cause: ErrorInfo) -> Self {
        self.error.cause = Some(Box::new(cause));
        self
    }

    /// Get the error information
    pub fn error_info(&self) -> &ErrorInfo {
        &self.error
    }

    /// Convert to different error context (for error propagation)
    pub fn map_context<NewContext>(self) -> TypeSafeError<NewContext> {
        TypeSafeError {
            error: self.error,
            _context: PhantomData,
        }
    }
}

/// Protocol-specific errors
impl TypeSafeError<error_contexts::Protocol> {
    /// Invalid JSON-RPC format
    pub fn invalid_json_rpc(message: String, request_id: Option<MessageId>) -> Self {
        Self {
            error: ErrorInfo {
                code: -32700, // JSON-RPC Parse error
                message,
                data: None,
                cause: None,
                request_id,
            },
            _context: PhantomData,
        }
    }

    /// Invalid request structure
    pub fn invalid_request(message: String, request_id: MessageId) -> Self {
        Self {
            error: ErrorInfo {
                code: -32600, // JSON-RPC Invalid Request
                message,
                data: None,
                cause: None,
                request_id: Some(request_id),
            },
            _context: PhantomData,
        }
    }

    /// Method not found
    pub fn method_not_found(method: String, request_id: MessageId) -> Self {
        Self {
            error: ErrorInfo {
                code: -32601, // JSON-RPC Method not found
                message: format!("Method not found: {method}"),
                data: Some(serde_json::json!({"method": method})),
                cause: None,
                request_id: Some(request_id),
            },
            _context: PhantomData,
        }
    }

    /// Invalid method parameters
    pub fn invalid_params(message: String, request_id: MessageId) -> Self {
        Self {
            error: ErrorInfo {
                code: -32602, // JSON-RPC Invalid params
                message,
                data: None,
                cause: None,
                request_id: Some(request_id),
            },
            _context: PhantomData,
        }
    }

    /// Internal protocol error
    pub fn internal_error(message: String, request_id: Option<MessageId>) -> Self {
        Self {
            error: ErrorInfo {
                code: -32603, // JSON-RPC Internal error
                message,
                data: None,
                cause: None,
                request_id,
            },
            _context: PhantomData,
        }
    }

    /// Protocol compliance error
    pub fn compliance_error(
        compliance_error: ProtocolComplianceError,
        request_id: MessageId,
    ) -> Self {
        Self {
            error: ErrorInfo {
                code: -32000, // Implementation-defined error
                message: format!("Protocol compliance error: {compliance_error}"),
                data: Some(serde_json::json!({
                    "compliance_error": compliance_error.to_string()
                })),
                cause: None,
                request_id: Some(request_id),
            },
            _context: PhantomData,
        }
    }
}

/// Tool execution errors
impl TypeSafeError<error_contexts::Tool> {
    /// Tool not found
    pub fn tool_not_found(tool_name: String, request_id: MessageId) -> Self {
        Self {
            error: ErrorInfo {
                code: 1001,
                message: format!("Tool not found: {tool_name}"),
                data: Some(serde_json::json!({"tool_name": tool_name})),
                cause: None,
                request_id: Some(request_id),
            },
            _context: PhantomData,
        }
    }

    /// Tool execution failed
    pub fn execution_failed(tool_name: String, reason: String, request_id: MessageId) -> Self {
        Self {
            error: ErrorInfo {
                code: 1002,
                message: format!("Tool execution failed: {reason}"),
                data: Some(serde_json::json!({
                    "tool_name": tool_name,
                    "reason": reason
                })),
                cause: None,
                request_id: Some(request_id),
            },
            _context: PhantomData,
        }
    }

    /// Tool timeout
    pub fn execution_timeout(
        tool_name: String,
        timeout_seconds: u32,
        request_id: MessageId,
    ) -> Self {
        Self {
            error: ErrorInfo {
                code: 1003,
                message: format!("Tool execution timed out after {timeout_seconds}s"),
                data: Some(serde_json::json!({
                    "tool_name": tool_name,
                    "timeout_seconds": timeout_seconds
                })),
                cause: None,
                request_id: Some(request_id),
            },
            _context: PhantomData,
        }
    }

    /// Resource limit exceeded
    pub fn resource_limit_exceeded(
        tool_name: String,
        resource: String,
        limit: String,
        request_id: MessageId,
    ) -> Self {
        Self {
            error: ErrorInfo {
                code: 1004,
                message: format!("Resource limit exceeded: {resource} limit is {limit}"),
                data: Some(serde_json::json!({
                    "tool_name": tool_name,
                    "resource": resource,
                    "limit": limit
                })),
                cause: None,
                request_id: Some(request_id),
            },
            _context: PhantomData,
        }
    }
}

/// Argument validation errors
impl TypeSafeError<error_contexts::Argument> {
    /// Invalid argument type
    pub fn invalid_type(
        argument: String,
        expected_type: String,
        actual_type: String,
        request_id: MessageId,
    ) -> Self {
        Self {
            error: ErrorInfo {
                code: 2001,
                message: format!(
                    "Invalid type for argument '{argument}': expected {expected_type}, got {actual_type}"
                ),
                data: Some(serde_json::json!({
                    "argument": argument,
                    "expected_type": expected_type,
                    "actual_type": actual_type
                })),
                cause: None,
                request_id: Some(request_id),
            },
            _context: PhantomData,
        }
    }

    /// Missing required argument
    pub fn missing_required(argument: String, request_id: MessageId) -> Self {
        Self {
            error: ErrorInfo {
                code: 2002,
                message: format!("Missing required argument: {argument}"),
                data: Some(serde_json::json!({"argument": argument})),
                cause: None,
                request_id: Some(request_id),
            },
            _context: PhantomData,
        }
    }

    /// Invalid argument value
    pub fn invalid_value(
        argument: String,
        value: String,
        reason: String,
        request_id: MessageId,
    ) -> Self {
        Self {
            error: ErrorInfo {
                code: 2003,
                message: format!("Invalid value '{value}' for argument '{argument}': {reason}"),
                data: Some(serde_json::json!({
                    "argument": argument,
                    "value": value,
                    "reason": reason
                })),
                cause: None,
                request_id: Some(request_id),
            },
            _context: PhantomData,
        }
    }

    /// Security constraint violation
    pub fn security_violation(reason: String, request_id: MessageId) -> Self {
        Self {
            error: ErrorInfo {
                code: 2004,
                message: format!("Security constraint violation: {reason}"),
                data: Some(serde_json::json!({"reason": reason})),
                cause: None,
                request_id: Some(request_id),
            },
            _context: PhantomData,
        }
    }

    /// Convert from ToolArgumentError
    pub fn from_tool_argument_error(error: ToolArgumentError, request_id: MessageId) -> Self {
        match error {
            ToolArgumentError::InvalidValue { field, reason } => {
                Self::invalid_value(field, "".to_string(), reason, request_id)
            }
            ToolArgumentError::SecurityViolation { reason } => {
                Self::security_violation(reason, request_id)
            }
            ToolArgumentError::DependencyConstraint { reason } => {
                Self::invalid_value("".to_string(), "".to_string(), reason, request_id)
            }
        }
    }
}

/// Command execution errors
impl TypeSafeError<error_contexts::Command> {
    /// Command execution failed
    pub fn execution_failed(
        command: String,
        exit_code: Option<i32>,
        stderr: String,
        request_id: MessageId,
    ) -> Self {
        Self {
            error: ErrorInfo {
                code: 3001,
                message: format!("Command execution failed: {command}"),
                data: Some(serde_json::json!({
                    "command": command,
                    "exit_code": exit_code,
                    "stderr": stderr
                })),
                cause: None,
                request_id: Some(request_id),
            },
            _context: PhantomData,
        }
    }

    /// Command not allowed by security policy
    pub fn security_violation(command: String, reason: String, request_id: MessageId) -> Self {
        Self {
            error: ErrorInfo {
                code: 3002,
                message: format!("Command blocked by security policy: {reason}"),
                data: Some(serde_json::json!({
                    "command": command,
                    "reason": reason
                })),
                cause: None,
                request_id: Some(request_id),
            },
            _context: PhantomData,
        }
    }

    /// Insufficient privileges for command
    pub fn insufficient_privileges(
        command: String,
        required: String,
        request_id: MessageId,
    ) -> Self {
        Self {
            error: ErrorInfo {
                code: 3003,
                message: format!("Insufficient privileges to execute command: {required} required"),
                data: Some(serde_json::json!({
                    "command": command,
                    "required": required
                })),
                cause: None,
                request_id: Some(request_id),
            },
            _context: PhantomData,
        }
    }
}

/// Authentication errors
impl TypeSafeError<error_contexts::Authentication> {
    /// Authentication failed
    pub fn authentication_failed(reason: String, request_id: Option<MessageId>) -> Self {
        Self {
            error: ErrorInfo {
                code: 4001,
                message: format!("Authentication failed: {reason}"),
                data: None, // Don't leak auth details
                cause: None,
                request_id,
            },
            _context: PhantomData,
        }
    }

    /// Insufficient permissions
    pub fn insufficient_permissions(resource: String, request_id: MessageId) -> Self {
        Self {
            error: ErrorInfo {
                code: 4002,
                message: format!("Insufficient permissions to access: {resource}"),
                data: Some(serde_json::json!({"resource": resource})),
                cause: None,
                request_id: Some(request_id),
            },
            _context: PhantomData,
        }
    }

    /// Token expired
    pub fn token_expired(request_id: MessageId) -> Self {
        Self {
            error: ErrorInfo {
                code: 4003,
                message: "Authentication token has expired".to_string(),
                data: None,
                cause: None,
                request_id: Some(request_id),
            },
            _context: PhantomData,
        }
    }
}

/// Transport errors
impl TypeSafeError<error_contexts::Transport> {
    /// Connection error
    pub fn connection_error(reason: String, request_id: Option<MessageId>) -> Self {
        Self {
            error: ErrorInfo {
                code: 5001,
                message: format!("Connection error: {reason}"),
                data: Some(serde_json::json!({"reason": reason})),
                cause: None,
                request_id,
            },
            _context: PhantomData,
        }
    }

    /// Stream error
    pub fn stream_error(reason: String, request_id: Option<MessageId>) -> Self {
        Self {
            error: ErrorInfo {
                code: 5002,
                message: format!("Stream error: {reason}"),
                data: Some(serde_json::json!({"reason": reason})),
                cause: None,
                request_id,
            },
            _context: PhantomData,
        }
    }

    /// Timeout error
    pub fn timeout_error(timeout_ms: u64, request_id: Option<MessageId>) -> Self {
        Self {
            error: ErrorInfo {
                code: 5003,
                message: format!("Operation timed out after {timeout_ms}ms"),
                data: Some(serde_json::json!({"timeout_ms": timeout_ms})),
                cause: None,
                request_id,
            },
            _context: PhantomData,
        }
    }
}

/// Error conversion trait for type-safe error propagation
pub trait ErrorConversion<FromContext, ToContext> {
    /// Convert an error from one context to another
    fn convert_error(error: TypeSafeError<FromContext>) -> TypeSafeError<ToContext>;
}

/// Convert argument errors to protocol errors
impl ErrorConversion<error_contexts::Argument, error_contexts::Protocol> for ErrorInfo {
    fn convert_error(
        error: TypeSafeError<error_contexts::Argument>,
    ) -> TypeSafeError<error_contexts::Protocol> {
        let request_id = error
            .error
            .request_id
            .clone()
            .unwrap_or(MessageId::Number(0));
        let error_clone = error.error.clone();
        TypeSafeError::<error_contexts::Protocol>::invalid_params(error.error.message, request_id)
            .with_cause(error_clone)
    }
}

/// Convert command errors to tool errors
impl ErrorConversion<error_contexts::Command, error_contexts::Tool> for ErrorInfo {
    fn convert_error(
        error: TypeSafeError<error_contexts::Command>,
    ) -> TypeSafeError<error_contexts::Tool> {
        let request_id = error
            .error
            .request_id
            .clone()
            .unwrap_or(MessageId::Number(0));
        let error_code = error.error.code;
        let error_message = error.error.message.clone();
        let error_clone = error.error.clone();

        match error_code {
            3001 => TypeSafeError::<error_contexts::Tool>::execution_failed(
                "command".to_string(),
                error_message.clone(),
                request_id,
            )
            .with_cause(error_clone),
            3002 => TypeSafeError::<error_contexts::Tool>::execution_failed(
                "command".to_string(),
                format!("Security violation: {error_message}"),
                request_id,
            )
            .with_cause(error_clone),
            3003 => TypeSafeError::<error_contexts::Tool>::execution_failed(
                "command".to_string(),
                format!("Insufficient privileges: {error_message}"),
                request_id,
            )
            .with_cause(error_clone),
            _ => TypeSafeError::<error_contexts::Tool>::execution_failed(
                "command".to_string(),
                error_message,
                request_id,
            )
            .with_cause(error_clone),
        }
    }
}

/// Result type for type-safe operations
pub type TypeSafeResult<T, Context> = Result<T, TypeSafeError<Context>>;

/// Convenience type aliases
pub type ProtocolResult<T> = TypeSafeResult<T, error_contexts::Protocol>;
pub type ToolResult<T> = TypeSafeResult<T, error_contexts::Tool>;
pub type ArgumentResult<T> = TypeSafeResult<T, error_contexts::Argument>;
pub type CommandResult<T> = TypeSafeResult<T, error_contexts::Command>;
pub type AuthResult<T> = TypeSafeResult<T, error_contexts::Authentication>;
pub type TransportResult<T> = TypeSafeResult<T, error_contexts::Transport>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_errors() {
        let error = TypeSafeError::<error_contexts::Protocol>::method_not_found(
            "invalid_method".to_string(),
            MessageId::Number(1),
        );

        assert_eq!(error.error_info().code, -32601);
        assert!(error.error_info().message.contains("invalid_method"));
        assert_eq!(error.error_info().request_id, Some(MessageId::Number(1)));
    }

    #[test]
    fn test_tool_errors() {
        let error = TypeSafeError::<error_contexts::Tool>::tool_not_found(
            "nonexistent_tool".to_string(),
            MessageId::Number(2),
        );

        assert_eq!(error.error_info().code, 1001);
        assert!(error.error_info().message.contains("nonexistent_tool"));
    }

    #[test]
    fn test_argument_errors() {
        let tool_error = ToolArgumentError::SecurityViolation {
            reason: "Dangerous command".to_string(),
        };

        let error = TypeSafeError::<error_contexts::Argument>::from_tool_argument_error(
            tool_error,
            MessageId::Number(3),
        );

        assert_eq!(error.error_info().code, 2004);
        assert!(error.error_info().message.contains("Dangerous command"));
    }

    #[test]
    fn test_error_with_cause() {
        let cause = ErrorInfo {
            code: 1000,
            message: "Root cause".to_string(),
            data: None,
            cause: None,
            request_id: None,
        };

        let error = TypeSafeError::<error_contexts::Protocol>::internal_error(
            "Internal error with cause".to_string(),
            Some(MessageId::Number(4)),
        )
        .with_cause(cause);

        assert!(error.error_info().cause.is_some());
        let cause_info = error.error_info().cause.as_ref().unwrap();
        assert_eq!(cause_info.code, 1000);
        assert_eq!(cause_info.message, "Root cause");
    }

    #[test]
    fn test_context_mapping() {
        let protocol_error = TypeSafeError::<error_contexts::Protocol>::internal_error(
            "Test error".to_string(),
            None,
        );

        let tool_error: TypeSafeError<error_contexts::Tool> = protocol_error.map_context();
        assert_eq!(tool_error.error_info().message, "Test error");
    }
}
