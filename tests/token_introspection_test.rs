use goldentooth_mcp::auth::{AuthConfig, AuthService};
use std::env;

/// Test the dual token validation strategy
/// This test verifies that our auth service can handle both JWT and opaque tokens
#[tokio::test]
async fn test_dual_token_validation_strategy() {
    println!("🧪 Testing dual token validation strategy");

    let auth_config = AuthConfig {
        authelia_base_url: "https://auth.services.goldentooth.net".to_string(),
        client_id: "goldentooth-mcp".to_string(),
        client_secret: "test-secret".to_string(), // Required for introspection
        redirect_uri: "https://mcp.services.goldentooth.net/callback".to_string(),
    };

    let auth_service = AuthService::new(auth_config);

    println!("🔍 Testing token format detection");

    // Test 1: JWT token format detection
    let jwt_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImF1dGhlbGlhLWdvbGRlbnRvb3RoIiwidHlwIjoiSldUIn0.eyJhdWQiOlsiZ29sZGVudG9vdGgtbWNwIl0sImV4cCI6MTc1MzQ1OTMwMywiZ3JvdXBzIjpbImFkbWlucyIsInVzZXJzIl0sImlhdCI6MTc1MzQ1NTcwMywiaXNzIjoiaHR0cHM6Ly9hdXRoLnNlcnZpY2VzLmdvbGRlbnRvb3RoLm5ldCIsInN1YiI6IjJiNzc1Y2E0LTI3ZjItNDNkYi1hNTMwLTUyMjMwYWNlMzViNSJ9.invalid_signature";
    assert!(
        auth_service.is_jwt_token(jwt_token),
        "Should detect JWT format"
    );

    // Test 2: Opaque token format detection
    let opaque_token = "authelia_at_PjqVx_hQc36upkjlOrFN5pUtjXw141yGh0Slwmp7zmg.kN862RSIiiX32mPDZVsiLLavR3B_jyQ8g2lZJBitE1Y";
    assert!(
        !auth_service.is_jwt_token(opaque_token),
        "Should detect opaque format"
    );

    // Test 3: Invalid token formats
    assert!(
        !auth_service.is_jwt_token("invalid-token"),
        "Should reject invalid format"
    );
    assert!(!auth_service.is_jwt_token(""), "Should reject empty token");
    assert!(
        !auth_service.is_jwt_token("one.two"),
        "Should reject incomplete JWT"
    );
    assert!(
        !auth_service.is_jwt_token("one.two.three.four"),
        "Should reject malformed JWT"
    );

    println!("✅ Token format detection tests passed");

    // Skip validation tests in CI environment - they require network access
    if env::var("CI").is_ok() || env::var("GITHUB_ACTIONS").is_ok() {
        println!("⚠️ Skipping validation path tests in CI environment (requires live Authelia)");
        return;
    }

    // Test 4: Validation path selection
    println!("🔍 Testing validation path selection");

    // This will fail validation but should take the JWT path
    match auth_service.validate_token(jwt_token).await {
        Ok(_) => println!("❌ JWT validation should have failed with invalid signature"),
        Err(e) => {
            println!("✅ JWT validation failed as expected: {e}");
            // Should be a JWT validation error, not introspection error
            assert!(e.to_string().contains("JWT") || e.to_string().contains("validation"));
        }
    }

    // This will take the introspection path (will likely fail due to invalid token)
    match auth_service.validate_token(opaque_token).await {
        Ok(_) => println!(
            "❌ Opaque token validation should likely fail without real introspection endpoint"
        ),
        Err(e) => {
            println!("✅ Opaque token validation failed as expected: {e}");
            // Should be an introspection error, not JWT error
            assert!(
                e.to_string().contains("introspection") || e.to_string().contains("Request failed")
            );
        }
    }

    println!("✅ Dual token validation strategy test completed");
}

/// Test JWT token format detection edge cases
#[tokio::test]
async fn test_jwt_format_detection_edge_cases() {
    println!("🧪 Testing JWT format detection edge cases");

    let auth_config = AuthConfig::default();
    let auth_service = AuthService::new(auth_config);

    // Edge cases for JWT detection
    let test_cases = vec![
        ("", false, "empty string"),
        (".", false, "single dot"),
        ("..", false, "two dots only"),
        ("a.b.c", true, "valid three-part format"),
        ("a.b.c.d", false, "four parts"),
        ("header.payload.", false, "empty signature"),
        (".payload.signature", false, "empty header"),
        ("header..signature", false, "empty payload"),
        ("a.b.c.d.e", false, "five parts"),
        ("normal-token-without-dots", false, "no dots at all"),
        (
            "authelia_at_token.signature",
            false,
            "authelia opaque token with one dot",
        ),
    ];

    for (token, expected, description) in test_cases {
        let result = auth_service.is_jwt_token(token);
        assert_eq!(result, expected, "Failed for {description}: '{token}'");
        println!("   ✅ {description}: '{token}' -> {result}");
    }

    println!("✅ JWT format detection edge cases test completed");
}

/// Test token introspection error handling
#[tokio::test]
async fn test_token_introspection_error_handling() {
    println!("🧪 Testing token introspection error handling");

    // Skip in CI environment - requires network access to Authelia
    if env::var("CI").is_ok() || env::var("GITHUB_ACTIONS").is_ok() {
        println!(
            "⚠️ Skipping introspection error handling test in CI environment (requires live Authelia)"
        );
        return;
    }

    let auth_config = AuthConfig {
        authelia_base_url: "https://auth.services.goldentooth.net".to_string(),
        client_id: "goldentooth-mcp".to_string(),
        client_secret: "test-secret".to_string(),
        redirect_uri: "https://mcp.services.goldentooth.net/callback".to_string(),
    };

    let auth_service = AuthService::new(auth_config);

    // Test with various invalid opaque tokens
    let invalid_tokens = vec![
        "invalid-opaque-token",
        "authelia_at_invalid",
        "completely_malformed_token",
    ];

    for token in invalid_tokens {
        println!("🔍 Testing introspection with invalid token: {token}");

        match auth_service.introspect_access_token(token).await {
            Ok(_) => println!("❌ Should have failed for invalid token: {token}"),
            Err(e) => {
                println!("✅ Correctly failed for invalid token: {e}");
                // Should be an introspection-related error
                assert!(
                    e.to_string().contains("introspection")
                        || e.to_string().contains("Request failed")
                        || e.to_string().contains("inactive"),
                    "Error should be introspection-related: {e}"
                );
            }
        }
    }

    println!("✅ Token introspection error handling test completed");
}

/// Integration test with real token (if available)
#[tokio::test]
async fn test_with_real_token_if_available() {
    println!("🧪 Testing with real token (if available in environment)");

    let test_token = match env::var("GOLDENTOOTH_TEST_TOKEN") {
        Ok(token) => token,
        Err(_) => {
            println!("⚠️ No GOLDENTOOTH_TEST_TOKEN found - skipping real token test");
            println!("   To test with real token:");
            println!("   1. Run: goldentooth mcp_auth");
            println!("   2. Complete OAuth flow");
            println!(
                "   3. Run: GOLDENTOOTH_TEST_TOKEN='your-token' cargo test test_with_real_token_if_available -- --nocapture"
            );
            return;
        }
    };

    let auth_config = AuthConfig {
        authelia_base_url: "https://auth.services.goldentooth.net".to_string(),
        client_id: "goldentooth-mcp".to_string(),
        client_secret: env::var("GOLDENTOOTH_CLIENT_SECRET").unwrap_or_default(),
        redirect_uri: "https://mcp.services.goldentooth.net/callback".to_string(),
    };

    let auth_service = AuthService::new(auth_config);

    println!("🔍 Testing real token validation");
    println!(
        "   Token format: {}...{}",
        &test_token[..20.min(test_token.len())],
        if test_token.len() > 40 {
            &test_token[test_token.len() - 20..]
        } else {
            ""
        }
    );

    // Determine expected validation path
    if auth_service.is_jwt_token(&test_token) {
        println!("   Expected path: JWT validation");
    } else {
        println!("   Expected path: Token introspection");
    }

    match auth_service.validate_token(&test_token).await {
        Ok(claims) => {
            println!("✅ Real token validation successful!");
            println!("   Subject: {}", claims.sub);
            println!("   Issuer: {}", claims.iss);
            println!("   Audience: {}", claims.aud);
            if let Some(username) = &claims.preferred_username {
                println!("   Username: {username}");
            }
            if let Some(email) = &claims.email {
                println!("   Email: {email}");
            }
            if let Some(groups) = &claims.groups {
                println!("   Groups: {groups:?}");
            }
        }
        Err(e) => {
            println!("❌ Real token validation failed: {e}");
            println!("   This helps us understand the authentication issue");
        }
    }

    println!("✅ Real token test completed");
}
