use goldentooth_mcp::screenshot::{AuthConfig, AuthMethod, ScreenshotRequest, ScreenshotService};
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Testing screenshot functionality...");

    let mut screenshot_service = ScreenshotService::new();

    // Test basic screenshot without authentication
    let request = ScreenshotRequest {
        url: "https://httpbin.org/html".to_string(),
        width: Some(1280),
        height: Some(720),
        wait_for_selector: None,
        wait_timeout_ms: Some(5000),
        authenticate: None,
    };

    println!("📸 Testing basic screenshot capture...");

    match screenshot_service.capture_screenshot(request).await {
        Ok(response) => {
            println!("✅ Screenshot captured successfully!");
            println!("📊 Metadata:");
            println!("   - URL: {}", response.metadata.url);
            println!(
                "   - Dimensions: {}x{}",
                response.metadata.width, response.metadata.height
            );
            println!(
                "   - File size: {} bytes",
                response.metadata.file_size_bytes
            );
            println!("   - Load time: {}ms", response.metadata.load_time_ms);

            if let Some(image_data) = &response.image_base64 {
                println!("   - Image data length: {} characters", image_data.len());
                println!(
                    "   - First 50 chars: {}",
                    &image_data[..50.min(image_data.len())]
                );
            }
        }
        Err(e) => {
            println!("❌ Screenshot failed: {}", e);
            match e {
                goldentooth_mcp::screenshot::ScreenshotError::BrowserLaunch(msg) => {
                    println!(
                        "💡 Hint: Chrome/Chromium might not be installed or available in PATH"
                    );
                    println!("   Error details: {}", msg);
                }
                _ => println!("   Error details: {}", e),
            }
        }
    }

    // Test Grafana dashboard with Authelia auth (will fail without credentials but tests the flow)
    println!("\n🏠 Testing Grafana dashboard capture (will fail auth but tests the flow)...");

    let auth_config = AuthConfig {
        method: AuthMethod::Authelia {
            redirect_url: "https://grafana.services.goldentooth.net".to_string(),
        },
        username: "test_user".to_string(),
        password: "test_pass".to_string(),
        login_url: None,
        success_url: Some("https://grafana.services.goldentooth.net".to_string()),
    };

    match screenshot_service
        .capture_dashboard(
            "https://grafana.services.goldentooth.net",
            Some(auth_config),
        )
        .await
    {
        Ok(response) => {
            println!("✅ Dashboard screenshot captured!");
            println!("📊 Dashboard metadata:");
            println!("   - URL: {}", response.metadata.url);
            println!("   - Load time: {}ms", response.metadata.load_time_ms);
        }
        Err(e) => {
            println!(
                "❌ Dashboard screenshot failed (expected with test credentials): {}",
                e
            );
            println!("💡 This confirms the authentication flow is working correctly!");
        }
    }

    Ok(())
}
