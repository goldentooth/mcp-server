//! Protocol state machine using phantom types
//!
//! This module implements a compile-time state machine for MCP protocol compliance
//! using phantom types. This ensures that protocol transitions are valid and prevents
//! illegal protocol states at compile time.

use std::marker::PhantomData;

/// Phantom type markers for protocol states
pub mod states {
    /// Initial state - no protocol handshake completed
    pub struct Uninitialized;

    /// Initialization in progress - initialize request sent/received
    pub struct Initializing;

    /// Protocol handshake complete - can process requests
    pub struct Initialized;

    /// Protocol error state - connection should be terminated
    pub struct Error;

    /// Protocol shutdown in progress
    pub struct ShuttingDown;

    /// Protocol connection closed
    pub struct Closed;
}

/// Type-safe protocol state machine
#[derive(Debug)]
pub struct ProtocolState<S> {
    _state: PhantomData<S>,
    /// Optional error information for Error state
    error_info: Option<String>,
    /// Protocol version negotiated during initialization
    protocol_version: Option<String>,
    /// Client information from initialization
    client_info: Option<ClientInfo>,
}

#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

impl<S> ProtocolState<S> {
    /// Get error information if in Error state
    pub fn error_info(&self) -> Option<&str> {
        self.error_info.as_deref()
    }

    /// Get negotiated protocol version
    pub fn protocol_version(&self) -> Option<&str> {
        self.protocol_version.as_deref()
    }

    /// Get client information
    pub fn client_info(&self) -> Option<&ClientInfo> {
        self.client_info.as_ref()
    }
}

/// Protocol state transitions
impl Default for ProtocolState<states::Uninitialized> {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolState<states::Uninitialized> {
    /// Create a new uninitialized protocol state
    pub fn new() -> Self {
        Self {
            _state: PhantomData,
            error_info: None,
            protocol_version: None,
            client_info: None,
        }
    }

    /// Transition to initializing state when initialize request is received
    pub fn begin_initialization(self) -> ProtocolState<states::Initializing> {
        ProtocolState {
            _state: PhantomData,
            error_info: None,
            protocol_version: None,
            client_info: None,
        }
    }

    /// Transition directly to error state if protocol violation occurs
    pub fn error(self, error: String) -> ProtocolState<states::Error> {
        ProtocolState {
            _state: PhantomData,
            error_info: Some(error),
            protocol_version: None,
            client_info: None,
        }
    }
}

impl ProtocolState<states::Initializing> {
    /// Complete initialization successfully
    pub fn complete_initialization(
        self,
        protocol_version: String,
        client_info: ClientInfo,
    ) -> ProtocolState<states::Initialized> {
        ProtocolState {
            _state: PhantomData,
            error_info: None,
            protocol_version: Some(protocol_version),
            client_info: Some(client_info),
        }
    }

    /// Initialization failed
    pub fn initialization_failed(self, error: String) -> ProtocolState<states::Error> {
        ProtocolState {
            _state: PhantomData,
            error_info: Some(error),
            protocol_version: None,
            client_info: None,
        }
    }
}

impl ProtocolState<states::Initialized> {
    /// Protocol error occurred during normal operation
    pub fn protocol_error(self, error: String) -> ProtocolState<states::Error> {
        ProtocolState {
            _state: PhantomData,
            error_info: Some(error),
            protocol_version: self.protocol_version,
            client_info: self.client_info,
        }
    }

    /// Begin graceful shutdown
    pub fn begin_shutdown(self) -> ProtocolState<states::ShuttingDown> {
        ProtocolState {
            _state: PhantomData,
            error_info: None,
            protocol_version: self.protocol_version,
            client_info: self.client_info,
        }
    }
}

impl ProtocolState<states::ShuttingDown> {
    /// Complete shutdown
    pub fn complete_shutdown(self) -> ProtocolState<states::Closed> {
        ProtocolState {
            _state: PhantomData,
            error_info: None,
            protocol_version: None,
            client_info: None,
        }
    }

    /// Error during shutdown
    pub fn shutdown_error(self, error: String) -> ProtocolState<states::Error> {
        ProtocolState {
            _state: PhantomData,
            error_info: Some(error),
            protocol_version: self.protocol_version,
            client_info: self.client_info,
        }
    }
}

impl ProtocolState<states::Error> {
    /// Force close connection after error
    pub fn force_close(self) -> ProtocolState<states::Closed> {
        ProtocolState {
            _state: PhantomData,
            error_info: None,
            protocol_version: None,
            client_info: None,
        }
    }
}

/// Type-safe protocol operations
pub trait ProtocolOperations<S> {
    type State;

    /// Check if the protocol can accept new requests
    fn can_accept_requests(&self) -> bool;

    /// Check if the protocol is in a terminal state
    fn is_terminal(&self) -> bool;
}

impl ProtocolOperations<states::Uninitialized> for ProtocolState<states::Uninitialized> {
    type State = states::Uninitialized;

    fn can_accept_requests(&self) -> bool {
        false // Only initialize request allowed
    }

    fn is_terminal(&self) -> bool {
        false
    }
}

impl ProtocolOperations<states::Initializing> for ProtocolState<states::Initializing> {
    type State = states::Initializing;

    fn can_accept_requests(&self) -> bool {
        false // Must complete initialization first
    }

    fn is_terminal(&self) -> bool {
        false
    }
}

impl ProtocolOperations<states::Initialized> for ProtocolState<states::Initialized> {
    type State = states::Initialized;

    fn can_accept_requests(&self) -> bool {
        true // Can process all MCP requests
    }

    fn is_terminal(&self) -> bool {
        false
    }
}

impl ProtocolOperations<states::Error> for ProtocolState<states::Error> {
    type State = states::Error;

    fn can_accept_requests(&self) -> bool {
        false // No requests allowed in error state
    }

    fn is_terminal(&self) -> bool {
        true
    }
}

impl ProtocolOperations<states::ShuttingDown> for ProtocolState<states::ShuttingDown> {
    type State = states::ShuttingDown;

    fn can_accept_requests(&self) -> bool {
        false // No new requests during shutdown
    }

    fn is_terminal(&self) -> bool {
        false
    }
}

impl ProtocolOperations<states::Closed> for ProtocolState<states::Closed> {
    type State = states::Closed;

    fn can_accept_requests(&self) -> bool {
        false // Connection closed
    }

    fn is_terminal(&self) -> bool {
        true
    }
}

/// Type-safe method validation
pub trait AllowedMethods<S> {
    /// Check if a method is allowed in the current state
    fn is_method_allowed(&self, method: &str) -> bool;

    /// Get list of allowed methods in current state
    fn allowed_methods(&self) -> &'static [&'static str];
}

impl AllowedMethods<states::Uninitialized> for ProtocolState<states::Uninitialized> {
    fn is_method_allowed(&self, method: &str) -> bool {
        method == "initialize"
    }

    fn allowed_methods(&self) -> &'static [&'static str] {
        &["initialize"]
    }
}

impl AllowedMethods<states::Initializing> for ProtocolState<states::Initializing> {
    fn is_method_allowed(&self, _method: &str) -> bool {
        // During initialization, no other methods are allowed
        false
    }

    fn allowed_methods(&self) -> &'static [&'static str] {
        &[] // Must complete initialization first
    }
}

impl AllowedMethods<states::Initialized> for ProtocolState<states::Initialized> {
    fn is_method_allowed(&self, method: &str) -> bool {
        matches!(
            method,
            "ping"
                | "tools/list"
                | "tools/call"
                | "resources/list"
                | "resources/read"
                | "prompts/list"
                | "prompts/get"
        )
    }

    fn allowed_methods(&self) -> &'static [&'static str] {
        &[
            "ping",
            "tools/list",
            "tools/call",
            "resources/list",
            "resources/read",
            "prompts/list",
            "prompts/get",
        ]
    }
}

impl AllowedMethods<states::Error> for ProtocolState<states::Error> {
    fn is_method_allowed(&self, _method: &str) -> bool {
        false // No methods allowed in error state
    }

    fn allowed_methods(&self) -> &'static [&'static str] {
        &[]
    }
}

impl AllowedMethods<states::ShuttingDown> for ProtocolState<states::ShuttingDown> {
    fn is_method_allowed(&self, _method: &str) -> bool {
        false // No methods allowed during shutdown
    }

    fn allowed_methods(&self) -> &'static [&'static str] {
        &[]
    }
}

impl AllowedMethods<states::Closed> for ProtocolState<states::Closed> {
    fn is_method_allowed(&self, _method: &str) -> bool {
        false // Connection closed
    }

    fn allowed_methods(&self) -> &'static [&'static str] {
        &[]
    }
}

/// Protocol compliance checker
pub struct ProtocolCompliance;

impl ProtocolCompliance {
    /// Validate that a request is allowed in the current protocol state
    pub fn validate_request<S>(
        state: &ProtocolState<S>,
        method: &str,
    ) -> Result<(), ProtocolComplianceError>
    where
        ProtocolState<S>: AllowedMethods<S> + ProtocolOperations<S>,
    {
        // First check if the method is allowed (this handles special cases like 'initialize')
        if !state.is_method_allowed(method) {
            return Err(ProtocolComplianceError::MethodNotAllowed {
                method: method.to_string(),
                current_state: std::any::type_name::<S>().to_string(),
                allowed_methods: state
                    .allowed_methods()
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            });
        }

        // For allowed methods, check if the state can accept requests
        // (This allows 'initialize' in uninitialized state since it's in the allowed_methods)
        if !state.can_accept_requests() && !matches!(method, "initialize") {
            return Err(ProtocolComplianceError::RequestsNotAllowed {
                current_state: std::any::type_name::<S>().to_string(),
            });
        }

        Ok(())
    }
}

/// Protocol compliance errors
#[derive(Debug, Clone, PartialEq)]
pub enum ProtocolComplianceError {
    /// Requests are not allowed in current state
    RequestsNotAllowed { current_state: String },
    /// Method is not allowed in current state
    MethodNotAllowed {
        method: String,
        current_state: String,
        allowed_methods: Vec<String>,
    },
    /// Invalid state transition attempted
    InvalidTransition {
        from_state: String,
        to_state: String,
    },
}

impl std::fmt::Display for ProtocolComplianceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolComplianceError::RequestsNotAllowed { current_state } => {
                write!(f, "Requests not allowed in state: {current_state}")
            }
            ProtocolComplianceError::MethodNotAllowed {
                method,
                current_state,
                allowed_methods,
            } => {
                write!(
                    f,
                    "Method '{method}' not allowed in state {current_state}. Allowed methods: {}",
                    allowed_methods.join(", ")
                )
            }
            ProtocolComplianceError::InvalidTransition {
                from_state,
                to_state,
            } => {
                write!(f, "Invalid transition from {from_state} to {to_state}")
            }
        }
    }
}

impl std::error::Error for ProtocolComplianceError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_state_transitions() {
        // Start uninitialized
        let state = ProtocolState::new();
        assert!(!state.can_accept_requests());
        assert!(state.is_method_allowed("initialize"));
        assert!(!state.is_method_allowed("ping"));

        // Begin initialization
        let state = state.begin_initialization();
        assert!(!state.can_accept_requests());
        assert!(!state.is_method_allowed("initialize"));
        assert!(!state.is_method_allowed("ping"));

        // Complete initialization
        let client_info = ClientInfo {
            name: "test-client".to_string(),
            version: "1.0.0".to_string(),
        };
        let state = state.complete_initialization("2024-11-05".to_string(), client_info);
        assert!(state.can_accept_requests());
        assert!(!state.is_method_allowed("initialize"));
        assert!(state.is_method_allowed("ping"));
        assert!(state.is_method_allowed("tools/call"));

        // Error state
        let state = state.protocol_error("Test error".to_string());
        assert!(!state.can_accept_requests());
        assert!(state.is_terminal());
        assert_eq!(state.error_info(), Some("Test error"));
    }

    #[test]
    fn test_protocol_compliance_validation() {
        let state = ProtocolState::new();

        // Initialize should be allowed in uninitialized state
        assert!(ProtocolCompliance::validate_request(&state, "initialize").is_ok());

        // Ping should not be allowed in uninitialized state
        let result = ProtocolCompliance::validate_request(&state, "ping");
        assert!(result.is_err());

        // Complete initialization cycle and test
        let state = state.begin_initialization();
        let client_info = ClientInfo {
            name: "test-client".to_string(),
            version: "1.0.0".to_string(),
        };
        let state = state.complete_initialization("2024-11-05".to_string(), client_info);

        // Now ping should be allowed
        assert!(ProtocolCompliance::validate_request(&state, "ping").is_ok());
        assert!(ProtocolCompliance::validate_request(&state, "tools/call").is_ok());
    }

    #[test]
    fn test_initialization_failure() {
        let state = ProtocolState::new();
        let state = state.begin_initialization();
        let state = state.initialization_failed("Invalid protocol version".to_string());

        assert!(!state.can_accept_requests());
        assert!(state.is_terminal());
        assert_eq!(state.error_info(), Some("Invalid protocol version"));
    }
}
