use goldentooth_mcp::auth::{AuthConfig, AuthService};
use goldentooth_mcp::http_server::HttpServer;
use goldentooth_mcp::service::GoldentoothService;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, StatusCode, body::Bytes};
use serde_json::{Value, json};
use std::collections::HashMap;
use tokio::net::TcpListener;
use tokio::time::{Duration, sleep};
use url::Url;

// Mock OAuth server for testing
struct MockOAuthServer {
    port: u16,
    authorization_code: String,
    access_token: String,
}

impl MockOAuthServer {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        Self {
            port,
            authorization_code: "mock_auth_code_12345".to_string(),
            access_token: "mock_access_token_67890".to_string(),
        }
    }

    async fn start(&self) {
        let authorization_code = self.authorization_code.clone();
        let access_token = self.access_token.clone();
        let port = self.port;

        tokio::spawn(async move {
            let listener = TcpListener::bind(format!("127.0.0.1:{port}"))
                .await
                .unwrap();

            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let io = hyper_util::rt::TokioIo::new(stream);
                let authorization_code = authorization_code.clone();
                let access_token = access_token.clone();

                tokio::task::spawn(async move {
                    let service_fn = hyper::service::service_fn(move |req| {
                        let authorization_code = authorization_code.clone();
                        let access_token = access_token.clone();
                        async move {
                            handle_mock_oauth_request(req, authorization_code, access_token).await
                        }
                    });

                    if let Err(err) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service_fn)
                        .await
                    {
                        eprintln!("Mock OAuth server error: {err:?}");
                    }
                });
            }
        });

        // Give the server a moment to start
        sleep(Duration::from_millis(200)).await;
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

async fn handle_mock_oauth_request(
    req: Request<hyper::body::Incoming>,
    authorization_code: String,
    access_token: String,
) -> Result<hyper::Response<Full<Bytes>>, std::convert::Infallible> {
    let path = req.uri().path();
    let method = req.method();

    match (method, path) {
        // OIDC Discovery endpoint
        (&Method::GET, "/.well-known/openid-configuration") => {
            // Extract port from Host header if authority is not available
            let port = if let Some(authority) = req.uri().authority() {
                authority.port().map(|p| p.as_u16()).unwrap_or(8080)
            } else if let Some(host_header) = req.headers().get("host") {
                host_header
                    .to_str()
                    .unwrap_or("127.0.0.1:8080")
                    .split(':')
                    .nth(1)
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(8080)
            } else {
                8080
            };
            let base_url = format!("http://127.0.0.1:{port}");
            let discovery = json!({
                "issuer": base_url,
                "authorization_endpoint": format!("{}/api/oidc/authorization", base_url),
                "token_endpoint": format!("{}/api/oidc/token", base_url),
                "userinfo_endpoint": format!("{}/api/oidc/userinfo", base_url),
                "jwks_uri": format!("{}/jwks.json", base_url),
                "scopes_supported": ["offline_access", "openid", "profile", "groups", "email"],
                "response_types_supported": ["code", "id_token", "token", "id_token token", "code id_token", "code token", "code id_token token"],
                "grant_types_supported": ["authorization_code", "implicit", "client_credentials", "refresh_token"]
            });

            Ok(hyper::Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(discovery.to_string())))
                .unwrap())
        }
        // Authorization endpoint - simulate user login
        (&Method::GET, "/api/oidc/authorization") => {
            let query = req.uri().query().unwrap_or("");
            let mut params = HashMap::new();
            for pair in query.split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    params.insert(key, value);
                }
            }

            let redirect_uri = params
                .get("redirect_uri")
                .unwrap_or(&"http://localhost:8080/callback");
            let state = params.get("state").unwrap_or(&"");

            // Simulate successful authorization with redirect
            let redirect_url = format!("{redirect_uri}?code={authorization_code}&state={state}");

            Ok(hyper::Response::builder()
                .status(StatusCode::FOUND)
                .header("Location", redirect_url)
                .body(Full::new(Bytes::new()))
                .unwrap())
        }
        // Token endpoint - exchange code for token
        (&Method::POST, "/api/oidc/token") => {
            let body = req.collect().await.unwrap().to_bytes();
            let body_str = String::from_utf8(body.to_vec()).unwrap();

            // Check if the request contains our mock authorization code
            if body_str.contains(&authorization_code) {
                let token_response = json!({
                    "access_token": access_token,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": "openid profile email"
                });

                Ok(hyper::Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(token_response.to_string())))
                    .unwrap())
            } else {
                let error_response = json!({
                    "error": "invalid_grant",
                    "error_description": "Authorization code is invalid"
                });

                Ok(hyper::Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(error_response.to_string())))
                    .unwrap())
            }
        }
        // JWKS endpoint - minimal mock
        (&Method::GET, "/jwks.json") => {
            let jwks = json!({
                "keys": []
            });

            Ok(hyper::Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(jwks.to_string())))
                .unwrap())
        }
        _ => Ok(hyper::Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("Not Found")))
            .unwrap()),
    }
}

/// Test Claude Code-style endpoint discovery and OAuth flow
#[tokio::test]
async fn test_end_to_end_oauth_flow() {
    // 1. Start mock OAuth server (simulates Authelia)
    let mock_oauth = MockOAuthServer::new().await;
    mock_oauth.start().await;

    // 2. Configure MCP server to use our mock OAuth server
    let auth_config = AuthConfig {
        authelia_base_url: mock_oauth.base_url(),
        client_id: "test-client".to_string(),
        client_secret: "test-secret".to_string(),
        redirect_uri: "http://localhost:8080/callback".to_string(),
    };

    let mut auth_service = AuthService::new(auth_config);

    // Retry initialization a few times to handle timing issues with mock server
    let mut retries = 3;
    while retries > 0 {
        match auth_service.initialize().await {
            Ok(_) => break,
            Err(e) if retries > 1 => {
                println!("Auth service initialization failed, retrying... Error: {e}");
                sleep(Duration::from_millis(500)).await;
                retries -= 1;
            }
            Err(e) => panic!("Failed to initialize auth service after retries: {e}"),
        }
    }

    let goldentooth_service = GoldentoothService::new();
    let http_server = HttpServer::new(goldentooth_service, Some(auth_service));

    // 3. Start MCP HTTP server
    let mcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mcp_port = mcp_listener.local_addr().unwrap().port();
    drop(mcp_listener);

    let server_handle = {
        tokio::spawn(async move {
            let addr = format!("127.0.0.1:{mcp_port}").parse().unwrap();
            http_server.serve(addr).await.unwrap();
        })
    };

    // Give servers time to start
    sleep(Duration::from_millis(200)).await;

    let mcp_base_url = format!("http://127.0.0.1:{mcp_port}");

    // 4. Test Step 1: Claude Code discovers OAuth metadata (this was failing with HTTP 405)
    println!("🔍 Step 1: Testing OAuth metadata discovery...");

    let client = reqwest::Client::new();
    let metadata_response = client
        .get(format!(
            "{mcp_base_url}/.well-known/oauth-authorization-server"
        ))
        .send()
        .await
        .expect("Failed to fetch OAuth metadata");

    assert_eq!(metadata_response.status(), reqwest::StatusCode::OK);

    let metadata: Value = metadata_response
        .json()
        .await
        .expect("Failed to parse metadata JSON");

    // Verify the metadata contains required OAuth fields
    assert!(metadata["issuer"].is_string());
    assert!(metadata["authorization_endpoint"].is_string());
    assert!(metadata["token_endpoint"].is_string());
    assert!(metadata["jwks_uri"].is_string());

    println!("✅ OAuth metadata discovery successful");

    // 5. Test Step 2: Get authorization URL
    println!("🔗 Step 2: Getting authorization URL...");

    let auth_url_response = client
        .post(format!("{mcp_base_url}/auth/authorize"))
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("Failed to get authorization URL");

    assert_eq!(auth_url_response.status(), reqwest::StatusCode::OK);

    let auth_data: Value = auth_url_response
        .json()
        .await
        .expect("Failed to parse auth response");
    let authorization_url = auth_data["authorization_url"]
        .as_str()
        .expect("Missing authorization_url");

    println!("✅ Authorization URL obtained: {authorization_url}");

    // 6. Test Step 3: Simulate user following authorization URL (gets redirected with code)
    println!("👤 Step 3: Simulating user authorization...");

    // Create a client that doesn't follow redirects so we can capture the redirect URL
    let no_redirect_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let auth_response = no_redirect_client
        .get(authorization_url)
        .send()
        .await
        .expect("Failed to follow authorization URL");

    assert_eq!(auth_response.status(), reqwest::StatusCode::FOUND);

    let location = auth_response
        .headers()
        .get("location")
        .expect("Missing location header");
    let location_str = location.to_str().expect("Invalid location header");

    println!("Redirect URL: {location_str}");

    // Extract authorization code from redirect URL
    let code = extract_code_from_redirect(location_str).expect("Failed to extract code");
    assert_eq!(code, mock_oauth.authorization_code);

    println!("✅ User authorization simulation successful, code: {code}");

    // 7. Test Step 4: Exchange authorization code for access token
    println!("🔑 Step 4: Exchanging code for access token...");

    let token_request = json!({
        "code": code
    });

    let token_response = client
        .post(format!("{mcp_base_url}/auth/token"))
        .header("Content-Type", "application/json")
        .body(token_request.to_string())
        .send()
        .await
        .expect("Failed to exchange code for token");

    assert_eq!(token_response.status(), reqwest::StatusCode::OK);

    let token_data: Value = token_response
        .json()
        .await
        .expect("Failed to parse token response");
    let access_token = token_data["access_token"]
        .as_str()
        .expect("Missing access_token");
    assert_eq!(access_token, mock_oauth.access_token);

    println!("✅ Token exchange successful");

    // 8. Test Step 5: Verify access token is present and properly formatted
    println!("🔐 Step 5: Verifying access token format...");

    // In a real scenario, Claude Code would use this token for MCP requests
    // For our test, we just verify the token looks right and could be used
    assert!(!access_token.is_empty());
    assert_eq!(access_token, mock_oauth.access_token);

    println!("✅ Access token format verified - ready for MCP requests");

    // 6. Test Step 6: Verify HEAD requests work correctly
    println!("🔍 Step 6: Testing HEAD request behavior...");

    let head_response = client
        .head(format!(
            "{mcp_base_url}/.well-known/oauth-authorization-server"
        ))
        .send()
        .await
        .expect("Failed to make HEAD request");

    assert_eq!(head_response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        head_response.headers().get("content-type").unwrap(),
        "application/json"
    );

    // HEAD response should have empty body
    let head_body = head_response
        .text()
        .await
        .expect("Failed to read HEAD response body");
    assert!(head_body.is_empty());

    println!("✅ HEAD request behavior correct");

    // 7. Test Step 7: Test unauthenticated request fails properly
    println!("🚫 Step 7: Testing unauthenticated request handling...");

    let mcp_request = json!({
        "jsonrpc": "2.0",
        "method": "server/get_info",
        "id": 1
    });

    let unauth_response = client
        .post(format!("{mcp_base_url}/mcp/request"))
        .header("Content-Type", "application/json")
        .body(mcp_request.to_string())
        .send()
        .await
        .expect("Failed to make unauthenticated request");

    assert_eq!(unauth_response.status(), reqwest::StatusCode::UNAUTHORIZED);

    println!("✅ Unauthenticated request properly rejected");

    // Cleanup
    server_handle.abort();

    println!("🎉 End-to-end OAuth flow test completed successfully!");
}

/// Test that simulates the exact error scenario that was happening
#[tokio::test]
async fn test_claude_code_discovery_scenario() {
    // This test specifically reproduces the HTTP 405 error that Claude Code was encountering

    let mock_oauth = MockOAuthServer::new().await;
    mock_oauth.start().await;

    let auth_config = AuthConfig {
        authelia_base_url: mock_oauth.base_url(),
        client_id: "goldentooth-mcp".to_string(),
        client_secret: "test-secret".to_string(),
        redirect_uri: "https://mcp.services.goldentooth.net/callback".to_string(),
    };

    let mut auth_service = AuthService::new(auth_config);

    // Retry initialization a few times to handle timing issues with mock server
    let mut retries = 3;
    while retries > 0 {
        match auth_service.initialize().await {
            Ok(_) => break,
            Err(e) if retries > 1 => {
                println!("Auth service initialization failed, retrying... Error: {e}");
                sleep(Duration::from_millis(500)).await;
                retries -= 1;
            }
            Err(e) => panic!("Failed to initialize auth service after retries: {e}"),
        }
    }

    let goldentooth_service = GoldentoothService::new();
    let http_server = HttpServer::new(goldentooth_service, Some(auth_service));

    let mcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mcp_port = mcp_listener.local_addr().unwrap().port();
    drop(mcp_listener);

    let _server_handle = {
        tokio::spawn(async move {
            let addr = format!("127.0.0.1:{mcp_port}").parse().unwrap();
            http_server.serve(addr).await.unwrap();
        })
    };

    sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{mcp_port}");

    // Test the exact requests that Claude Code makes during OAuth discovery

    // 1. Try to discover OAuth metadata (this was returning HTTP 405 before our fix)
    let oauth_metadata_response = client
        .get(format!("{base_url}/.well-known/oauth-authorization-server"))
        .send()
        .await
        .expect("Failed to fetch OAuth metadata");

    // This should now work (was returning 405 before)
    assert_eq!(oauth_metadata_response.status(), reqwest::StatusCode::OK);

    // 2. Also test the OpenID Connect discovery endpoint
    let oidc_metadata_response = client
        .get(format!("{base_url}/.well-known/openid-configuration"))
        .send()
        .await
        .expect("Failed to fetch OIDC metadata");

    assert_eq!(oidc_metadata_response.status(), reqwest::StatusCode::OK);

    // 3. Verify both return the same metadata (as implemented)
    let oauth_metadata: Value = oauth_metadata_response.json().await.unwrap();
    let oidc_metadata: Value = oidc_metadata_response.json().await.unwrap();

    assert_eq!(oauth_metadata, oidc_metadata);

    // 4. Test that unsupported methods on OAuth endpoints fall through to regular processing
    // (This is actually correct behavior - our OAuth endpoints only handle GET/HEAD,
    // other methods fall through to the main request handler)
    let post_response = client
        .post(format!("{base_url}/.well-known/oauth-authorization-server"))
        .send()
        .await
        .expect("Failed to make POST request");

    // Should return 200 because auth service is configured and can provide OAuth metadata
    assert_eq!(post_response.status(), reqwest::StatusCode::OK);

    println!("✅ Claude Code discovery scenario test passed - HTTP 405 error fixed!");
}

/// Helper function to extract authorization code from redirect URL
fn extract_code_from_redirect(redirect_url: &str) -> Option<String> {
    // First decode the URL if it's URL-encoded
    let decoded_url = urlencoding::decode(redirect_url).ok()?;
    let url = Url::parse(&decoded_url).ok()?;
    url.query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.to_string())
}

/// Test various error scenarios to ensure robust error handling
#[tokio::test]
async fn test_oauth_error_scenarios() {
    let goldentooth_service = GoldentoothService::new();

    // Test 1: No auth service configured
    let http_server_no_auth = HttpServer::new(goldentooth_service.clone(), None);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let _server_handle = {
        tokio::spawn(async move {
            let addr = format!("127.0.0.1:{port}").parse().unwrap();
            http_server_no_auth.serve(addr).await.unwrap();
        })
    };

    sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{port}");

    // Should return 404 when OAuth not configured
    let response = client
        .get(format!("{base_url}/.well-known/oauth-authorization-server"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);

    let error_data: Value = response.json().await.unwrap();
    assert_eq!(error_data["error"], "OAuth not configured");

    println!("✅ Error scenario test passed - proper error handling verified");
}
