use goldentooth_mcp::auth::{AuthConfig, AuthService};
use goldentooth_mcp::http_server::HttpServer;
use goldentooth_mcp::service::GoldentoothService;
use reqwest;
use serde_json::{Value, json};
use std::env;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::sleep;

/// Test with a real JWT token from environment variable
/// Set GOLDENTOOTH_TEST_TOKEN to run this test with a real token
#[tokio::test]
async fn test_with_real_jwt_token() {
    println!("🧪 Testing with real JWT token (if available)");

    // Check for test token in environment
    let test_token = match env::var("GOLDENTOOTH_TEST_TOKEN") {
        Ok(token) => token,
        Err(_) => {
            println!("⚠️ No test token provided. Set GOLDENTOOTH_TEST_TOKEN to run this test.");
            println!("   To get a token:");
            println!("   1. Run: goldentooth mcp_auth");
            println!("   2. Complete OAuth flow");
            println!("   3. Copy token from logs/response");
            println!(
                "   4. Run: GOLDENTOOTH_TEST_TOKEN='your-token' cargo test test_with_real_jwt_token -- --nocapture"
            );
            return;
        }
    };

    println!(
        "📝 Testing with token: {}...{}",
        &test_token[..20],
        &test_token[test_token.len() - 20..]
    );

    let auth_config = AuthConfig {
        authelia_base_url: "https://auth.services.goldentooth.net".to_string(),
        client_id: "goldentooth-mcp".to_string(),
        client_secret: "".to_string(),
        redirect_uri: "https://mcp.services.goldentooth.net/callback".to_string(),
    };

    let auth_service = AuthService::new(auth_config);
    let goldentooth_service = GoldentoothService::new();
    let http_server = HttpServer::new(goldentooth_service, Some(auth_service.clone()));

    // Start test server
    let test_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let test_port = test_listener.local_addr().unwrap().port();
    drop(test_listener);

    let _server_handle = tokio::spawn(async move {
        let addr = format!("127.0.0.1:{}", test_port).parse().unwrap();
        http_server.serve(addr).await.unwrap();
    });

    sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}", test_port);

    println!("🔍 Testing MCP request with real token");

    let mcp_request = json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "0.1.0",
            "capabilities": {}
        },
        "id": 1
    });

    let response = client
        .post(&format!("{}/mcp/request", base_url))
        .header("Authorization", format!("Bearer {}", test_token))
        .json(&mcp_request)
        .send()
        .await
        .expect("Failed to make MCP request");

    let status = response.status();
    println!("   Response status: {}", status);
    let response_text = response.text().await.unwrap();
    println!("   Response body: {}", response_text);

    if status == reqwest::StatusCode::OK {
        println!("✅ Token validation succeeded!");
        let response_json: Value = serde_json::from_str(&response_text).unwrap();
        println!(
            "   MCP Response: {}",
            serde_json::to_string_pretty(&response_json).unwrap()
        );
    } else {
        println!("❌ Token validation failed with status: {}", status);
        println!("   This helps us understand what's going wrong:");

        // Parse error response if it's JSON
        if let Ok(error_json) = serde_json::from_str::<Value>(&response_text) {
            println!(
                "   Error details: {}",
                serde_json::to_string_pretty(&error_json).unwrap()
            );
        } else {
            println!("   Raw error: {}", response_text);
        }
    }

    // Also test the token validation directly
    println!("🔍 Testing token validation directly");

    match auth_service.validate_token(&test_token).await {
        Ok(claims) => {
            println!("✅ Direct token validation succeeded!");
            println!("   Claims: {:?}", claims);
        }
        Err(e) => {
            println!("❌ Direct token validation failed: {}", e);
            println!("   This tells us exactly what's wrong with JWT validation");
        }
    }
}

/// Helper test to extract token info without validation
#[tokio::test]
async fn test_token_inspection() {
    println!("🧪 Testing token inspection (no validation)");

    let test_token = match env::var("GOLDENTOOTH_TEST_TOKEN") {
        Ok(token) => token,
        Err(_) => {
            println!("⚠️ No test token provided. Set GOLDENTOOTH_TEST_TOKEN to inspect token.");
            return;
        }
    };

    // Split JWT into parts
    let parts: Vec<&str> = test_token.split('.').collect();
    if parts.len() != 3 {
        println!("❌ Invalid JWT format (should have 3 parts separated by dots)");
        return;
    }

    println!("📋 JWT Structure:");
    println!("   Header: {}", parts[0]);
    println!("   Payload: {}", parts[1]);
    println!(
        "   Signature: {}...{}",
        &parts[2][..10],
        &parts[2][parts[2].len() - 10..]
    );

    // Try to decode header and payload (without verification)
    use base64::{Engine as _, engine::general_purpose};

    // Decode header
    if let Ok(header_bytes) = general_purpose::URL_SAFE_NO_PAD.decode(parts[0]) {
        if let Ok(header_str) = String::from_utf8(header_bytes) {
            if let Ok(header_json) = serde_json::from_str::<Value>(&header_str) {
                println!(
                    "📄 Header (decoded): {}",
                    serde_json::to_string_pretty(&header_json).unwrap()
                );
            }
        }
    }

    // Decode payload
    if let Ok(payload_bytes) = general_purpose::URL_SAFE_NO_PAD.decode(parts[1]) {
        if let Ok(payload_str) = String::from_utf8(payload_bytes) {
            if let Ok(payload_json) = serde_json::from_str::<Value>(&payload_str) {
                println!(
                    "📄 Payload (decoded): {}",
                    serde_json::to_string_pretty(&payload_json).unwrap()
                );

                // Check expiration
                if let Some(exp) = payload_json.get("exp").and_then(|e| e.as_i64()) {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;

                    println!("⏰ Token timing:");
                    println!("   Current time: {}", now);
                    println!("   Token expires: {}", exp);
                    println!("   Time difference: {} seconds", exp - now);

                    if exp < now {
                        println!("   ❌ Token is EXPIRED!");
                    } else if exp - now < 60 {
                        println!("   ⚠️ Token expires soon (less than 1 minute)");
                    } else {
                        println!("   ✅ Token is valid (time-wise)");
                    }
                }

                // Check issuer
                if let Some(iss) = payload_json.get("iss").and_then(|i| i.as_str()) {
                    println!("   Issuer: {}", iss);
                }

                // Check audience
                if let Some(aud) = payload_json.get("aud") {
                    println!("   Audience: {}", aud);
                }
            }
        }
    }

    println!("✅ Token inspection completed");
}

/// Test to get a fresh token using the auth flow
#[tokio::test]
async fn test_get_fresh_token() {
    println!("🧪 Testing fresh token acquisition");

    let auth_config = AuthConfig {
        authelia_base_url: "https://auth.services.goldentooth.net".to_string(),
        client_id: "goldentooth-mcp".to_string(),
        client_secret: env::var("GOLDENTOOTH_CLIENT_SECRET").unwrap_or_default(),
        redirect_uri: "https://mcp.services.goldentooth.net/callback".to_string(),
    };

    let auth_service = AuthService::new(auth_config);

    println!("🔍 Step 1: Getting authorization URL");
    match auth_service.get_authorization_url() {
        Ok((auth_url, _csrf_token)) => {
            println!("✅ Authorization URL: {}", auth_url);
            println!("📝 To complete this test:");
            println!("   1. Visit the URL above");
            println!("   2. Login and authorize");
            println!("   3. Copy the 'code' parameter from the callback URL");
            println!("   4. Set GOLDENTOOTH_AUTH_CODE env var and run token exchange test");
        }
        Err(e) => {
            println!("❌ Failed to get authorization URL: {}", e);
        }
    }

    // If we have an auth code, try to exchange it
    if let Ok(auth_code) = env::var("GOLDENTOOTH_AUTH_CODE") {
        println!("🔍 Step 2: Exchanging authorization code for token");

        match auth_service.exchange_code_for_token(&auth_code).await {
            Ok(access_token) => {
                println!("✅ Token exchange successful!");
                println!("   Access token: {}", access_token.secret());
                println!("📝 You can now test with:");
                println!(
                    "   GOLDENTOOTH_TEST_TOKEN='{}' cargo test test_with_real_jwt_token -- --nocapture",
                    access_token.secret()
                );
            }
            Err(e) => {
                println!("❌ Token exchange failed: {}", e);
                println!("   This might help us understand the OAuth flow issues");
            }
        }
    } else {
        println!("⚠️ No GOLDENTOOTH_AUTH_CODE provided - skipping token exchange");
    }
}
