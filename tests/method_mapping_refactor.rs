//! Tests for method string mapping refactoring
//!
//! This test module verifies that we can eliminate the duplication
//! between Display and FromStr implementations for McpMethod

use goldentooth_mcp::types::McpMethod;
use std::str::FromStr;

#[test]
fn test_method_roundtrip_consistency() {
    let methods = vec![
        McpMethod::Initialize,
        McpMethod::Ping,
        McpMethod::ToolsList,
        McpMethod::ToolsCall,
        McpMethod::ResourcesList,
        McpMethod::ResourcesRead,
        McpMethod::PromptsList,
        McpMethod::PromptsGet,
    ];

    for method in methods {
        // Convert to string using Display
        let method_str = method.to_string();

        // Parse back using FromStr
        let parsed_method = McpMethod::from_str(&method_str)
            .unwrap_or_else(|_| panic!("Failed to parse method string: {method_str}"));

        // Should be identical
        assert_eq!(
            method,
            parsed_method,
            "Method roundtrip failed for: {} -> {} -> {:?}",
            format!("{:?}", method),
            method_str,
            parsed_method
        );
    }
}

#[test]
fn test_all_methods_have_valid_string_representations() {
    let methods = vec![
        McpMethod::Initialize,
        McpMethod::Ping,
        McpMethod::ToolsList,
        McpMethod::ToolsCall,
        McpMethod::ResourcesList,
        McpMethod::ResourcesRead,
        McpMethod::PromptsList,
        McpMethod::PromptsGet,
    ];

    for method in methods {
        let method_str = method.to_string();

        // Should not be empty
        assert!(
            !method_str.is_empty(),
            "Method string should not be empty for {method:?}"
        );

        // Should contain valid characters (alphanumeric, slash, underscore)
        assert!(
            method_str
                .chars()
                .all(|c| c.is_alphanumeric() || c == '/' || c == '_'),
            "Method string '{method_str}' contains invalid characters"
        );

        // Should be parseable back to the same method
        let parsed = McpMethod::from_str(&method_str);
        assert!(
            parsed.is_ok(),
            "Failed to parse method string: {method_str}"
        );
        assert_eq!(
            parsed.unwrap(),
            method,
            "Parsed method doesn't match original for: {method_str}"
        );
    }
}

#[test]
fn test_invalid_method_strings_are_rejected() {
    let invalid_methods = vec![
        "",
        "invalid",
        "INITIALIZE", // wrong case
        "tools/CALL", // wrong case
        "unknown/method",
        "tools/list/extra",
        "123invalid",
    ];

    for invalid_method in invalid_methods {
        let result = McpMethod::from_str(invalid_method);
        assert!(
            result.is_err(),
            "Invalid method '{invalid_method}' should be rejected but was accepted"
        );
    }
}

#[test]
fn test_expected_method_strings() {
    // Test specific expected string representations
    assert_eq!(McpMethod::Initialize.to_string(), "initialize");
    assert_eq!(McpMethod::Ping.to_string(), "ping");
    assert_eq!(McpMethod::ToolsList.to_string(), "tools/list");
    assert_eq!(McpMethod::ToolsCall.to_string(), "tools/call");
    assert_eq!(McpMethod::ResourcesList.to_string(), "resources/list");
    assert_eq!(McpMethod::ResourcesRead.to_string(), "resources/read");
    assert_eq!(McpMethod::PromptsList.to_string(), "prompts/list");
    assert_eq!(McpMethod::PromptsGet.to_string(), "prompts/get");
}
