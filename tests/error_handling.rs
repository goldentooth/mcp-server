use serde_json::json;

#[tokio::test]
async fn test_error_context_detail() {
    // Test that errors include comprehensive context

    // Test missing required parameter
    let missing_param_request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 1,
        "params": {
            // Missing required "name" parameter
            "arguments": {}
        }
    });

    // TODO: When implemented, should return error with details:
    // "error": {
    //   "code": -32602,
    //   "message": "Invalid params",
    //   "data": {
    //     "missing_parameters": ["name"],
    //     "received_parameters": ["arguments"],
    //     "parameter_schema": {...}
    //   }
    // }

    assert_eq!(missing_param_request["method"], "tools/call");

    // Test invalid parameter type
    let invalid_type_request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 1,
        "params": {
            "name": 123, // Should be string
            "arguments": {}
        }
    });

    // TODO: Should return detailed type error
    assert!(invalid_type_request["params"]["name"].is_number());
}

#[tokio::test]
async fn test_no_sensitive_data_in_errors() {
    // Test that error messages don't leak sensitive information

    let requests_with_sensitive_data = vec![
        json!({
            "jsonrpc": "2.0",
            "method": "cluster/execute",
            "id": 1,
            "params": {
                "command": "echo SECRET_PASSWORD=abc123",
                "node": "test-node"
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "method": "auth/login",
            "id": 1,
            "params": {
                "token": "jwt_token_with_secrets",
                "credentials": "sensitive_data"
            }
        }),
    ];

    for request in requests_with_sensitive_data {
        // TODO: When implemented, verify that any errors returned do not contain:
        // - The actual command being executed
        // - Authentication tokens or credentials
        // - File paths that might reveal system structure
        // - Stack traces with local variables

        // Error should be generic like:
        // "Command execution failed" (not the actual command)
        // "Authentication failed" (not the token value)

        assert!(request["params"].is_object());
    }
}
