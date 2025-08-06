use goldentooth_mcp::auth::{AuthConfig, AuthService};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing Authelia OIDC integration...");

    // Set up auth config
    let auth_config = AuthConfig::default();
    println!("Auth config: {auth_config:?}");

    // Create auth service
    let mut auth_service = AuthService::new(auth_config);

    // Check if authentication is required
    if !auth_service.requires_auth() {
        println!("Authentication is disabled (OAUTH_CLIENT_SECRET not set or empty)");
        return Ok(()) as Result<(), Box<dyn std::error::Error>>;
    }

    println!("Authentication is enabled, initializing...");

    // Initialize the auth service
    match auth_service.initialize().await {
        Ok(_) => println!("✓ Successfully initialized OIDC client"),
        Err(e) => {
            eprintln!("✗ Failed to initialize OIDC client: {e}");
            return Err(Box::new(e));
        }
    }

    // Test OIDC discovery
    match auth_service.discover_oidc_config().await {
        Ok(discovery) => {
            println!("✓ OIDC Discovery successful:");
            println!("  Issuer: {}", discovery.issuer);
            println!(
                "  Authorization endpoint: {}",
                discovery.authorization_endpoint
            );
            println!("  Token endpoint: {}", discovery.token_endpoint);
            println!("  JWKS URI: {}", discovery.jwks_uri);
        }
        Err(e) => {
            eprintln!("✗ OIDC Discovery failed: {e}");
            return Err(Box::new(e));
        }
    }

    // Test JWKS endpoint
    match auth_service.get_jwks().await {
        Ok(jwks) => {
            println!(
                "✓ JWKS retrieval successful, found {} keys",
                jwks.keys.len()
            );
            for (i, key) in jwks.keys.iter().enumerate() {
                println!("  Key {}: ID={}, Type={}", i + 1, key.kid, key.kty);
            }
        }
        Err(e) => {
            eprintln!("✗ JWKS retrieval failed: {e}");
            return Err(Box::new(e));
        }
    }

    // Test authorization URL generation
    match auth_service.get_authorization_url() {
        Ok((auth_url, csrf_token)) => {
            println!("✓ Authorization URL generated:");
            println!("  URL: {auth_url}");
            println!("  CSRF Token: {}", csrf_token.secret());
        }
        Err(e) => {
            eprintln!("✗ Authorization URL generation failed: {e}");
            return Err(Box::new(e));
        }
    }

    // Test token validation if a token is provided
    if let Ok(test_token) = env::var("TEST_JWT_TOKEN") {
        println!("Testing JWT token validation...");
        match auth_service.validate_token(&test_token).await {
            Ok(claims) => {
                println!("✓ Token validation successful:");
                println!("  Subject: {}", claims.sub);
                println!("  Issuer: {}", claims.iss);
                println!("  Audience: {}", claims.aud);
                if let Some(email) = &claims.email {
                    println!("  Email: {email}");
                }
                if let Some(groups) = &claims.groups {
                    println!("  Groups: {groups:?}");
                }
            }
            Err(e) => {
                eprintln!("✗ Token validation failed: {e}");
                // This is not a fatal error since we might not have a valid token
            }
        }
    } else {
        println!("ℹ  Set TEST_JWT_TOKEN environment variable to test token validation");
    }

    println!("\n🎉 Authentication integration test completed successfully!");
    Ok(()) as Result<(), Box<dyn std::error::Error>>
}
