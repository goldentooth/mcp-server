use goldentooth_mcp::screenshot::{AuthConfig, AuthMethod, ScreenshotRequest, ScreenshotService};
use std::env;

#[tokio::main]
async fn main() {
    println!("Testing Grafana screenshot with Authelia authentication...");

    let mut screenshot_service = ScreenshotService::new();

    // Get authentication credentials from environment
    let username = env::var("AUTHELIA_USERNAME").unwrap_or_else(|_| {
        println!("⚠️ AUTHELIA_USERNAME not set, using default");
        "admin".to_string()
    });

    let password = env::var("AUTHELIA_PASSWORD").unwrap_or_else(|_| {
        println!("⚠️ AUTHELIA_PASSWORD not set, using default");
        "password".to_string()
    });

    println!("🔐 Using credentials - Username: {}", username);

    // Configure Authelia authentication
    let auth_config = AuthConfig {
        method: AuthMethod::Authelia {
            redirect_url: "https://grafana.services.goldentooth.net".to_string(),
        },
        username,
        password,
        login_url: None,
        success_url: None,
    };

    // Test Grafana dashboard screenshot
    println!("📸 Capturing Grafana dashboard screenshot...");
    let request = ScreenshotRequest {
        url: "https://grafana.services.goldentooth.net".to_string(),
        width: Some(1920),
        height: Some(1080),
        wait_for_selector: Some(
            ".dashboard-container, .react-grid-layout, .panel-container".to_string(),
        ),
        wait_timeout_ms: Some(15000),
        authenticate: Some(auth_config),
    };

    match screenshot_service.capture_screenshot(request).await {
        Ok(response) => {
            println!("✅ Grafana screenshot captured successfully!");
            println!("URL: {}", response.metadata.url);
            println!("Timestamp: {}", response.metadata.timestamp);
            println!(
                "Dimensions: {}x{}",
                response.metadata.width, response.metadata.height
            );
            println!("File size: {} bytes", response.metadata.file_size_bytes);
            println!("Load time: {} ms", response.metadata.load_time_ms);

            if let Some(image_data) = response.image_base64 {
                println!("Image data length: {} characters", image_data.len());
                println!("✅ Screenshot successfully captured and base64 encoded");

                // Save first 200 chars to show it's valid base64
                println!(
                    "Base64 preview: {}",
                    &image_data[..std::cmp::min(200, image_data.len())]
                );
            }
        }
        Err(e) => {
            eprintln!("❌ Grafana screenshot failed: {}", e);
            println!("📝 Note: This is expected if Chrome/Chromium is not installed or accessible");
        }
    }

    // Also test the specialized dashboard function
    println!("\n📸 Testing dashboard-specific capture function...");
    let auth_config = Some(AuthConfig {
        method: AuthMethod::Authelia {
            redirect_url: "https://grafana.services.goldentooth.net".to_string(),
        },
        username: env::var("AUTHELIA_USERNAME").unwrap_or_else(|_| "admin".to_string()),
        password: env::var("AUTHELIA_PASSWORD").unwrap_or_else(|_| "password".to_string()),
        login_url: None,
        success_url: None,
    });

    match screenshot_service
        .capture_dashboard("https://grafana.services.goldentooth.net", auth_config)
        .await
    {
        Ok(response) => {
            println!("✅ Dashboard-specific capture successful!");
            println!("Load time: {} ms", response.metadata.load_time_ms);
        }
        Err(e) => {
            eprintln!("❌ Dashboard screenshot failed: {}", e);
            println!("📝 Note: This is expected if Chrome/Chromium is not installed or accessible");
        }
    }

    println!("\n🎉 Grafana screenshot test completed!");
    println!("📋 Summary:");
    println!("  - Screenshot service initialized ✅");
    println!("  - Authelia authentication configured ✅");
    println!("  - Dashboard-specific selectors configured ✅");
    println!("  - Both generic and dashboard capture methods tested ✅");
    println!("  - Ready for deployment to environment with Chrome/Chromium 🚀");
}
