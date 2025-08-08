//! Tests for tool schema refactoring
//!
//! This test module verifies that we can extract tool schema generation
//! to eliminate duplication between tools/mod.rs and protocol.rs

use goldentooth_mcp::tools::get_all_tools;

#[tokio::test]
async fn test_tool_schemas_are_valid_json() {
    let tools = get_all_tools();

    for tool in tools {
        let schema = tool.input_schema();

        // Verify it's valid JSON
        assert!(
            schema.is_object(),
            "Tool {} schema should be an object",
            tool.name()
        );

        // Verify required fields
        assert!(
            schema["type"].is_string(),
            "Tool {} should have type field",
            tool.name()
        );
        assert_eq!(
            schema["type"],
            "object",
            "Tool {} type should be 'object'",
            tool.name()
        );

        // Verify properties field exists (can be empty)
        assert!(
            schema.get("properties").is_some(),
            "Tool {} should have properties field",
            tool.name()
        );
    }
}

#[tokio::test]
async fn test_tool_list_has_expected_tools() {
    let tools = get_all_tools();

    let expected_tools = vec![
        "cluster_ping",
        // Add more as they get implemented
    ];

    for expected in expected_tools {
        let found = tools.iter().any(|tool| tool.name() == expected);
        assert!(found, "Expected tool '{expected}' not found in tool list");
    }
}

#[tokio::test]
async fn test_tool_descriptions_are_not_empty() {
    let tools = get_all_tools();

    for tool in tools {
        assert!(
            !tool.description().is_empty(),
            "Tool {} should have a non-empty description",
            tool.name()
        );
        assert!(
            tool.description().len() > 10,
            "Tool {} description should be meaningful (>10 chars)",
            tool.name()
        );
    }
}

#[tokio::test]
async fn test_tool_names_are_valid() {
    let tools = get_all_tools();

    for tool in tools {
        let name = tool.name();
        assert!(!name.is_empty(), "Tool name should not be empty");
        assert!(
            name.chars().all(|c| c.is_alphanumeric() || c == '_'),
            "Tool name '{name}' should only contain alphanumeric chars and underscores"
        );
        assert!(
            name.chars().next().unwrap().is_alphabetic(),
            "Tool name '{name}' should start with a letter"
        );
    }
}

/// Test that we can generate a tools list response using the tool trait
#[tokio::test]
async fn test_tools_can_generate_list_response() {
    let tools = get_all_tools();
    let mut tool_definitions = Vec::new();

    for tool in tools {
        let definition = serde_json::json!({
            "name": tool.name(),
            "description": tool.description(),
            "inputSchema": tool.input_schema()
        });
        tool_definitions.push(definition);
    }

    // Verify we can create a tools list response
    assert!(
        !tool_definitions.is_empty(),
        "Should have at least one tool"
    );

    for def in &tool_definitions {
        assert!(def["name"].is_string());
        assert!(def["description"].is_string());
        assert!(def["inputSchema"].is_object());
    }
}
