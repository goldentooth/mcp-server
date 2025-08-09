//! Compile-time safety tests
//!
//! These tests demonstrate the compile-time safety guarantees provided by the
//! new type system. They show how illegal states are now unrepresentable and
//! how errors are caught at compile time rather than runtime.

use goldentooth_mcp::types::*;

#[test]
fn test_node_name_compile_time_safety() {
    // Valid node names compile successfully
    let valid_node = NodeName::new("allyrion").unwrap();
    assert_eq!(valid_node.as_str(), "allyrion");

    // Invalid node names are caught at the validation step
    let invalid_result = NodeName::new("invalid_node");
    assert!(invalid_result.is_err());

    // The type system ensures only valid nodes can be used
    let args = ClusterStatusArgs {
        node: Some(valid_node),
    };

    assert_eq!(args.node.unwrap().as_str(), "allyrion");
}

#[test]
fn test_shell_command_security_compile_time() {
    // Safe commands can be created
    let safe_cmd = ShellCommand::new("ls -la").unwrap();
    assert_eq!(safe_cmd.as_str(), "ls -la");

    // Dangerous commands are rejected at creation time
    let dangerous_result = ShellCommand::new("rm -rf /");
    assert!(dangerous_result.is_err());
    match dangerous_result {
        Err(ToolArgumentError::SecurityViolation { reason }) => {
            assert!(reason.contains("rm -rf"));
        }
        _ => panic!("Expected security violation"),
    }

    // The type system prevents dangerous commands from being used
    let safe_args = ShellCommandArgs {
        command: safe_cmd,
        node: None,
        as_root: None,
        timeout: None,
    };

    // This validates successfully because the command is already safe
    assert!(safe_args.validate().is_ok());
}

#[test]
fn test_protocol_state_transitions_compile_time() {
    // Protocol state transitions are enforced by the type system
    let state = ProtocolState::new();

    // Initialize method is allowed in uninitialized state
    assert!(ProtocolCompliance::validate_request(&state, "initialize").is_ok());

    // Ping method is not allowed in uninitialized state
    let result = ProtocolCompliance::validate_request(&state, "ping");
    assert!(result.is_err());
    match result {
        Err(ProtocolComplianceError::MethodNotAllowed { method, .. }) => {
            assert_eq!(method, "ping");
        }
        _ => panic!("Expected method not allowed error"),
    }

    // After initialization, different methods are allowed
    let state = state.begin_initialization();
    let client_info = ClientInfo {
        name: "test-client".to_string(),
        version: "1.0.0".to_string(),
    };
    let state = state.complete_initialization("2025-06-18".to_string(), client_info);

    // Now ping is allowed
    assert!(ProtocolCompliance::validate_request(&state, "ping").is_ok());
    assert!(ProtocolCompliance::validate_request(&state, "tools/call").is_ok());
}

#[test]
fn test_type_safe_error_contexts() {
    // Different error contexts are enforced at compile time
    let protocol_error = TypeSafeError::<error_contexts::Protocol>::method_not_found(
        "invalid_method".to_string(),
        MessageId::Number(1),
    );

    let tool_error = TypeSafeError::<error_contexts::Tool>::tool_not_found(
        "invalid_tool".to_string(),
        MessageId::Number(1),
    );

    // Error contexts prevent mixing up error types
    assert_eq!(protocol_error.error_info().code, -32601);
    assert_eq!(tool_error.error_info().code, 1001);

    // Error conversion is type-safe
    let converted: TypeSafeError<error_contexts::Tool> = protocol_error.map_context();
    assert_eq!(converted.error_info().code, -32601); // Code is preserved
}

#[test]
fn test_command_safety_analysis_compile_time() {
    // Command safety analysis provides compile-time guarantees
    let safe_result = CommandSafetyAnalyzer::analyze("ls -la");
    assert!(safe_result.is_executable());

    let dangerous_result = CommandSafetyAnalyzer::analyze("rm -rf /");
    assert!(!dangerous_result.is_executable());
    assert!(dangerous_result.rejection_reason().is_some());

    // Different safety levels have different constraints
    let context = ExecutionContext::safe_only();

    if let CommandAnalysisResult::Safe(cmd) = CommandSafetyAnalyzer::analyze("echo hello") {
        assert!(context.can_execute(&cmd).is_ok());
    }

    if let CommandAnalysisResult::Privileged(cmd) = CommandSafetyAnalyzer::analyze("journalctl") {
        assert!(context.can_execute_privileged(&cmd).is_err());
    }
}

#[test]
fn test_tool_arguments_type_safety() {
    // Tool arguments are type-safe and validated at creation

    // ServiceStatusArgs requires a service name
    let service = ServiceName::new("consul").unwrap();
    let args = ServiceStatusArgs {
        service,
        node: Some(NodeName::new("allyrion").unwrap()),
    };

    // Tool name is compile-time constant
    assert_eq!(ServiceStatusArgs::TOOL_NAME, "service_status");

    // Validation happens at the type level
    assert!(args.validate().is_ok());

    // Invalid service names are caught early
    let invalid_service = ServiceName::new("");
    assert!(invalid_service.is_err());
}

#[test]
fn test_url_validation_compile_time() {
    // URL validation prevents invalid URLs from being used
    let valid_url = HttpUrl::new("https://example.com").unwrap();
    let args = ScreenshotUrlArgs {
        url: valid_url,
        width: Some(1920),
        height: Some(1080),
        wait_for_selector: None,
        wait_timeout_ms: Some(5000),
    };

    assert!(args.validate().is_ok());

    // Invalid URLs are rejected
    let invalid_url = HttpUrl::new("not-a-url");
    assert!(invalid_url.is_err());

    let invalid_url = HttpUrl::new("ftp://example.com");
    assert!(invalid_url.is_err());
}

#[test]
fn test_logql_query_validation_compile_time() {
    // LogQL queries must be valid at construction time
    let valid_query = LogQLQuery::new(r#"{job="consul"}"#).unwrap();
    let args = LokiLogsArgs {
        query: valid_query,
        start: None,
        end: None,
        limit: Some(100),
        direction: Some(LogDirection::Backward),
    };

    assert!(args.validate().is_ok());

    // Invalid LogQL queries are rejected
    let invalid_query = LogQLQuery::new("invalid query");
    assert!(invalid_query.is_err());

    let empty_query = LogQLQuery::new("");
    assert!(empty_query.is_err());
}

#[test]
fn test_journald_logs_constraints() {
    // JournaldLogsArgs has specific constraints
    let args = JournaldLogsArgs {
        node: Some(NodeName::new("allyrion").unwrap()),
        service: Some(ServiceName::new("consul").unwrap()),
        priority: Some(LogPriority::Error),
        since: Some("1 hour ago".to_string()),
        lines: Some(50),
        follow: Some(false), // Follow must be false for MCP
    };

    assert!(args.validate().is_ok());

    // Follow mode is not allowed in MCP context
    let invalid_args = JournaldLogsArgs {
        node: None,
        service: None,
        priority: None,
        since: None,
        lines: None,
        follow: Some(true), // This should fail validation
    };

    let result = invalid_args.validate();
    assert!(result.is_err());
    match result {
        Err(ToolArgumentError::DependencyConstraint { reason }) => {
            assert!(reason.contains("Real-time log following"));
        }
        _ => panic!("Expected dependency constraint error"),
    }
}

#[test]
fn test_tool_args_union_type_safety() {
    // ToolArgs union type ensures type safety across all tools
    let cluster_ping = ToolArgs::ClusterPing(ClusterPingArgs::default());
    let cluster_status = ToolArgs::ClusterStatus(ClusterStatusArgs {
        node: Some(NodeName::new("jast").unwrap()),
    });

    // Tool names are consistent
    assert_eq!(cluster_ping.tool_name(), "cluster_ping");
    assert_eq!(cluster_status.tool_name(), "cluster_status");

    // All tool arguments can be validated
    assert!(cluster_ping.validate().is_ok());
    assert!(cluster_status.validate().is_ok());

    // Shell command with security validation
    let shell_cmd = ToolArgs::ShellCommand(ShellCommandArgs {
        command: ShellCommand::new("systemctl status consul").unwrap(),
        node: Some(NodeName::new("allyrion").unwrap()),
        as_root: Some(false),
        timeout: Some(30),
    });

    assert_eq!(shell_cmd.tool_name(), "shell_command");
    assert!(shell_cmd.validate().is_ok());
}

/// Compile-time test that certain invalid operations don't compile
///
/// These would be compile errors if uncommented:
/*
#[test]
fn test_compile_time_errors() {
    // This won't compile - can't create invalid node name directly
    // let invalid_node = NodeName("invalid_node".to_string()); // Private constructor

    // This won't compile - can't bypass command security
    // let dangerous_cmd = ShellCommand("rm -rf /".to_string()); // Private constructor

    // This won't compile - wrong error context
    // let wrong_context: TypeSafeError<error_contexts::Protocol> =
    //     TypeSafeError::<error_contexts::Tool>::tool_not_found("test".to_string(), MessageId::Number(1));

    // This won't compile - can't execute dangerous commands
    // let dangerous = SafeCommand::<safety_levels::Dangerous> { command: "rm -rf /".to_string(), _safety_level: PhantomData };
    // context.can_execute(&dangerous); // Dangerous doesn't implement Executable
}
*/

#[test]
fn test_type_safety_prevents_runtime_errors() {
    // The type system prevents many classes of runtime errors

    // 1. Invalid node names can't be constructed
    assert!(NodeName::new("invalid_node").is_err());

    // 2. Dangerous commands can't be constructed
    assert!(ShellCommand::new("rm -rf /").is_err());

    // 3. Invalid URLs can't be constructed
    assert!(HttpUrl::new("not-a-url").is_err());

    // 4. Invalid LogQL queries can't be constructed
    assert!(LogQLQuery::new("invalid").is_err());

    // 5. Empty service names can't be constructed
    assert!(ServiceName::new("").is_err());

    // 6. Protocol state transitions are enforced
    let state = ProtocolState::new();
    assert!(ProtocolCompliance::validate_request(&state, "tools/call").is_err());

    // 7. Command safety analysis prevents dangerous operations
    let result = CommandSafetyAnalyzer::analyze(":(){ :|:& };:");
    assert!(!result.is_executable());

    // All of these would have been runtime validation errors in the old system,
    // but are now caught at the type level or during construction
}
