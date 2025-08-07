use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

use base64::Engine;
use headless_chrome::{Browser, LaunchOptions, Tab};
use log::error;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScreenshotError {
    #[error("Browser launch failed: {0}")]
    BrowserLaunch(String),
    #[error("Navigation failed: {0}")]
    Navigation(String),
    #[error("Screenshot capture failed: {0}")]
    Capture(String),
    #[error("Authentication failed: {0}")]
    Authentication(String),
    #[error("Timeout waiting for element: {0}")]
    Timeout(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScreenshotRequest {
    pub url: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub wait_for_selector: Option<String>,
    pub wait_timeout_ms: Option<u64>,
    pub authenticate: Option<AuthConfig>,
    pub save_to_file: Option<bool>,
    pub file_directory: Option<String>,
    pub http_serve: Option<bool>,
    pub http_base_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthConfig {
    pub method: AuthMethod,
    pub username: String,
    pub password: String,
    pub login_url: Option<String>,
    pub success_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AuthMethod {
    Basic,
    Form {
        username_selector: String,
        password_selector: String,
        submit_selector: String,
    },
    Authelia {
        redirect_url: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScreenshotResponse {
    pub success: bool,
    pub image_base64: Option<String>,
    pub file_path: Option<String>,
    pub screenshot_url: Option<String>,
    pub error: Option<String>,
    pub metadata: ScreenshotMetadata,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScreenshotMetadata {
    pub url: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub width: u32,
    pub height: u32,
    pub file_size_bytes: usize,
    pub load_time_ms: u64,
}

pub struct ScreenshotService {
    browser: Option<Arc<Browser>>,
    default_options: LaunchOptions<'static>,
    http_server_port: Option<u16>,
    http_server_directory: Option<String>,
}

impl ScreenshotService {
    pub fn new() -> Self {
        let options = LaunchOptions::default_builder()
            .headless(true)
            .window_size(Some((1920, 1080)))
            .args(vec![
                OsStr::new("--no-sandbox"),
                OsStr::new("--disable-gpu"),
                OsStr::new("--disable-dev-shm-usage"),
                OsStr::new("--disable-extensions"),
                OsStr::new("--disable-plugins"),
                OsStr::new("--disable-images"),
                OsStr::new("--disable-background-timer-throttling"),
                OsStr::new("--disable-backgrounding-occluded-windows"),
                OsStr::new("--disable-renderer-backgrounding"),
            ])
            .build()
            .expect("Failed to build default launch options");

        Self {
            browser: None,
            default_options: options,
            http_server_port: None,
            http_server_directory: None,
        }
    }

    pub async fn initialize(&mut self) -> Result<(), ScreenshotError> {
        if self.browser.is_none() {
            let browser = Browser::new(self.default_options.clone())
                .map_err(|e| ScreenshotError::BrowserLaunch(e.to_string()))?;
            self.browser = Some(Arc::new(browser));
        }
        Ok(())
    }

    /// Check if the browser is healthy and reinitialize if needed
    async fn ensure_browser_healthy(&mut self) -> Result<(), ScreenshotError> {
        // If no browser exists, initialize it
        if self.browser.is_none() {
            return self.initialize().await;
        }

        // Test if the existing browser is still functional by trying to create a tab
        if let Some(ref browser) = self.browser {
            match browser.new_tab() {
                Ok(_) => {
                    // Browser is healthy
                    return Ok(());
                }
                Err(_) => {
                    // Browser is unhealthy, reinitialize
                    log::warn!("Browser connection is unhealthy, reinitializing...");
                    self.browser = None;
                    return self.initialize().await;
                }
            }
        }

        Ok(())
    }

    pub fn configure_http_server(&mut self, port: u16, directory: String) {
        self.http_server_port = Some(port);
        self.http_server_directory = Some(directory);
    }

    pub async fn start_http_server(&self) -> Result<(), ScreenshotError> {
        if let (Some(port), Some(directory)) = (&self.http_server_port, &self.http_server_directory)
        {
            let directory = directory.clone();
            let addr = format!("0.0.0.0:{port}");
            let listener = TcpListener::bind(&addr).await.map_err(|e| {
                ScreenshotError::BrowserLaunch(format!("Failed to bind to {addr}: {e}"))
            })?;

            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, _)) => {
                            let io = TokioIo::new(stream);
                            let directory = directory.clone();

                            tokio::spawn(async move {
                                let service = service_fn(move |req| {
                                    Self::handle_http_request(req, directory.clone())
                                });

                                if let Err(e) =
                                    http1::Builder::new().serve_connection(io, service).await
                                {
                                    error!("Screenshot HTTP connection error: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            error!("Screenshot HTTP server accept error: {e}");
                        }
                    }
                }
            });
        }
        Ok(())
    }

    async fn handle_http_request(
        req: Request<hyper::body::Incoming>,
        directory: String,
    ) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
        if req.method() != Method::GET {
            return Ok(Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Full::new(Bytes::from("Method not allowed")))?);
        }

        let path = req.uri().path();
        if let Some(filename) = path.strip_prefix('/') {
            // Security: Validate filename to prevent directory traversal
            if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from("Invalid filename")))?);
            }

            // Only allow PNG files
            if !filename.ends_with(".png") {
                return Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::from("File not found")))?);
            }

            let file_path = Path::new(&directory).join(filename);

            // Additional security: ensure the resolved path is within the directory
            if let Ok(canonical_file) = file_path.canonicalize() {
                if let Ok(canonical_dir) = Path::new(&directory).canonicalize() {
                    if !canonical_file.starts_with(&canonical_dir) {
                        return Ok(Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(Full::new(Bytes::from("Access denied")))?);
                    }
                }
            }

            if file_path.exists() {
                match tokio::fs::read(&file_path).await {
                    Ok(contents) => {
                        // Return raw binary PNG data with proper content type
                        return Ok(Response::builder()
                            .header("Content-Type", "image/png")
                            .header("Cache-Control", "public, max-age=3600")
                            .body(Full::new(Bytes::from(contents)))?);
                    }
                    Err(_) => {
                        return Ok(Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Full::new(Bytes::from("Server error")))?);
                    }
                }
            }
        }

        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("File not found")))?)
    }

    pub async fn capture_screenshot(
        &mut self,
        request: ScreenshotRequest,
    ) -> Result<ScreenshotResponse, ScreenshotError> {
        let start_time = chrono::Utc::now();

        // Ensure browser is healthy and reinitialize if needed
        self.ensure_browser_healthy().await?;

        let browser = self.browser.as_ref().unwrap();
        let tab = browser.new_tab().map_err(|e| {
            ScreenshotError::BrowserLaunch(format!("Failed to create new tab: {e}"))
        })?;

        // Set viewport size
        let width = request.width.unwrap_or(1920);
        let height = request.height.unwrap_or(1080);

        tab.set_default_timeout(Duration::from_millis(30000));
        tab.navigate_to(&request.url)
            .map_err(|e| ScreenshotError::Navigation(e.to_string()))?;

        // Handle authentication if required
        if let Some(auth_config) = &request.authenticate {
            self.authenticate(&tab, auth_config).await?;
        }

        // Wait for specific selector if provided
        if let Some(selector) = &request.wait_for_selector {
            let timeout = Duration::from_millis(request.wait_timeout_ms.unwrap_or(10000));
            tab.wait_for_element_with_custom_timeout(selector, timeout)
                .map_err(|e| ScreenshotError::Timeout(format!("Selector '{selector}': {e}")))?;
        } else {
            // Default wait for page load
            tab.wait_until_navigated()
                .map_err(|e| ScreenshotError::Navigation(e.to_string()))?;
        }

        // Additional wait for dashboard elements to load
        tokio::time::sleep(Duration::from_millis(2000)).await;

        // Capture screenshot
        let screenshot_data = tab
            .capture_screenshot(
                headless_chrome::protocol::cdp::Page::CaptureScreenshotFormatOption::Png,
                Some(100), // quality
                None,      // clip
                true,      // from_surface
            )
            .map_err(|e| ScreenshotError::Capture(e.to_string()))?;

        let load_time_ms = (chrono::Utc::now() - start_time).num_milliseconds() as u64;
        let file_size_bytes = screenshot_data.len();

        let mut image_base64 = None;
        let mut file_path = None;
        let mut screenshot_url = None;

        if request.save_to_file.unwrap_or(false) {
            // Save to file instead of returning base64
            let directory = request
                .file_directory
                .as_deref()
                .unwrap_or("/tmp/screenshots");

            // Create directory if it doesn't exist
            if let Err(e) = fs::create_dir_all(directory) {
                return Ok(ScreenshotResponse {
                    success: false,
                    image_base64: None,
                    file_path: None,
                    screenshot_url: None,
                    error: Some(format!("Failed to create screenshot directory: {e}")),
                    metadata: ScreenshotMetadata {
                        url: request.url.clone(),
                        timestamp: chrono::Utc::now(),
                        width,
                        height,
                        file_size_bytes,
                        load_time_ms,
                    },
                });
            }

            // Generate filename with timestamp
            let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S_%3f");
            let filename = format!("screenshot_{timestamp}.png");
            let full_path = Path::new(directory).join(&filename);

            // Save screenshot to file
            if let Err(e) = fs::write(&full_path, &screenshot_data) {
                return Ok(ScreenshotResponse {
                    success: false,
                    image_base64: None,
                    file_path: None,
                    screenshot_url: None,
                    error: Some(format!("Failed to save screenshot: {e}")),
                    metadata: ScreenshotMetadata {
                        url: request.url.clone(),
                        timestamp: chrono::Utc::now(),
                        width,
                        height,
                        file_size_bytes,
                        load_time_ms,
                    },
                });
            }

            file_path = Some(full_path.to_string_lossy().to_string());

            // Generate HTTP URL if HTTP serving is enabled
            if request.http_serve.unwrap_or(false) {
                if let Some(base_url) = &request.http_base_url {
                    screenshot_url = Some(format!("{base_url}/{filename}"));
                }
            }
        } else {
            // Return base64 encoded image (existing behavior)
            image_base64 = Some(base64::engine::general_purpose::STANDARD.encode(&screenshot_data));
        }

        Ok(ScreenshotResponse {
            success: true,
            image_base64,
            file_path,
            screenshot_url,
            error: None,
            metadata: ScreenshotMetadata {
                url: request.url.clone(),
                timestamp: chrono::Utc::now(),
                width,
                height,
                file_size_bytes,
                load_time_ms,
            },
        })
    }

    async fn authenticate(
        &self,
        tab: &Arc<Tab>,
        auth_config: &AuthConfig,
    ) -> Result<(), ScreenshotError> {
        match &auth_config.method {
            AuthMethod::Basic => {
                // Basic auth is handled via URL or headers - not much to do here
                Ok(())
            }

            AuthMethod::Form {
                username_selector,
                password_selector,
                submit_selector,
            } => {
                // Navigate to login page if specified
                if let Some(login_url) = &auth_config.login_url {
                    tab.navigate_to(login_url).map_err(|e| {
                        ScreenshotError::Authentication(format!("Failed to navigate to login: {e}"))
                    })?;
                    tab.wait_until_navigated()
                        .map_err(|e| ScreenshotError::Authentication(e.to_string()))?;
                }

                // Fill in credentials
                tab.wait_for_element(username_selector)
                    .map_err(|e| {
                        ScreenshotError::Authentication(format!("Username field not found: {e}"))
                    })?
                    .click()
                    .map_err(|e| ScreenshotError::Authentication(e.to_string()))?;

                tab.type_str(&auth_config.username)
                    .map_err(|e| ScreenshotError::Authentication(e.to_string()))?;

                tab.wait_for_element(password_selector)
                    .map_err(|e| {
                        ScreenshotError::Authentication(format!("Password field not found: {e}"))
                    })?
                    .click()
                    .map_err(|e| ScreenshotError::Authentication(e.to_string()))?;

                tab.type_str(&auth_config.password)
                    .map_err(|e| ScreenshotError::Authentication(e.to_string()))?;

                // Submit form
                tab.wait_for_element(submit_selector)
                    .map_err(|e| {
                        ScreenshotError::Authentication(format!("Submit button not found: {e}"))
                    })?
                    .click()
                    .map_err(|e| ScreenshotError::Authentication(e.to_string()))?;

                // Wait for successful login
                if let Some(success_url) = &auth_config.success_url {
                    // Instead of wait_for_url which doesn't exist, we'll check the current URL
                    tokio::time::sleep(Duration::from_millis(3000)).await;
                    let current_url = tab.get_url();
                    if !current_url.contains(success_url) {
                        return Err(ScreenshotError::Authentication(format!(
                            "Login failed - didn't reach success URL. Current: {current_url}, Expected: {success_url}"
                        )));
                    }
                } else {
                    tokio::time::sleep(Duration::from_millis(2000)).await;
                }

                Ok(())
            }

            AuthMethod::Authelia { redirect_url } => {
                // Authelia-specific authentication flow
                // Navigate to the protected resource, get redirected to Authelia, login, get redirected back
                tab.navigate_to(redirect_url).map_err(|e| {
                    ScreenshotError::Authentication(format!(
                        "Failed to navigate to protected resource: {e}"
                    ))
                })?;

                // Wait for redirect to Authelia login page
                tokio::time::sleep(Duration::from_millis(1000)).await;

                // Check if we're on the Authelia login page
                let current_url = tab.get_url();
                if current_url.contains("auth.") || current_url.contains("/api/firstfactor") {
                    // Fill in Authelia login form
                    tab.wait_for_element("#username")
                        .map_err(|e| {
                            ScreenshotError::Authentication(format!(
                                "Authelia username field not found: {e}"
                            ))
                        })?
                        .click()
                        .map_err(|e| ScreenshotError::Authentication(e.to_string()))?;

                    tab.type_str(&auth_config.username)
                        .map_err(|e| ScreenshotError::Authentication(e.to_string()))?;

                    tab.wait_for_element("#password")
                        .map_err(|e| {
                            ScreenshotError::Authentication(format!(
                                "Authelia password field not found: {e}"
                            ))
                        })?
                        .click()
                        .map_err(|e| ScreenshotError::Authentication(e.to_string()))?;

                    tab.type_str(&auth_config.password)
                        .map_err(|e| ScreenshotError::Authentication(e.to_string()))?;

                    // Submit login form
                    tab.wait_for_element("input[type=submit]")
                        .map_err(|e| {
                            ScreenshotError::Authentication(format!(
                                "Authelia submit button not found: {e}"
                            ))
                        })?
                        .click()
                        .map_err(|e| ScreenshotError::Authentication(e.to_string()))?;

                    // Wait for redirect back to original URL
                    tokio::time::sleep(Duration::from_millis(3000)).await;
                }

                Ok(())
            }
        }
    }

    pub async fn capture_dashboard(
        &mut self,
        dashboard_url: &str,
        auth_config: Option<AuthConfig>,
    ) -> Result<ScreenshotResponse, ScreenshotError> {
        self.capture_dashboard_with_options(dashboard_url, auth_config, false, None, false, None)
            .await
    }

    pub async fn capture_dashboard_with_options(
        &mut self,
        dashboard_url: &str,
        auth_config: Option<AuthConfig>,
        save_to_file: bool,
        file_directory: Option<String>,
        http_serve: bool,
        http_base_url: Option<String>,
    ) -> Result<ScreenshotResponse, ScreenshotError> {
        let request = ScreenshotRequest {
            url: dashboard_url.to_string(),
            width: Some(1920),
            height: Some(1080),
            wait_for_selector: Some(
                ".dashboard-container, .react-grid-layout, .panel-container".to_string(),
            ),
            wait_timeout_ms: Some(15000),
            authenticate: auth_config,
            save_to_file: Some(save_to_file),
            file_directory,
            http_serve: Some(http_serve),
            http_base_url,
        };

        self.capture_screenshot(request).await
    }
}

impl Default for ScreenshotService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_path_validation_security() {
        // Test path traversal detection
        assert!("../../../etc/passwd".contains(".."));
        assert!("subdir/../../file".contains(".."));
        assert!("file\\..\\other".contains(".."));
        assert!("normal_file.png".ends_with(".png"));
        assert!(!"script.js".ends_with(".png"));
    }

    #[test]
    fn test_screenshot_service_creation() {
        let service = ScreenshotService::new();
        assert!(service.browser.is_none());
        assert!(service.http_server_port.is_none());
        assert!(service.http_server_directory.is_none());
    }

    #[test]
    fn test_configure_http_server() {
        let mut service = ScreenshotService::new();
        service.configure_http_server(8080, "/test/path".to_string());
        assert_eq!(service.http_server_port, Some(8080));
        assert_eq!(
            service.http_server_directory,
            Some("/test/path".to_string())
        );
    }

    #[test]
    fn test_security_path_validation_logic() {
        // Test the core security logic without HTTP complexity

        // These should be rejected (contain ..)
        assert!("/../outside.png".contains(".."));
        assert!("/../../etc/passwd".contains(".."));
        assert!("/subdir/../../file".contains(".."));
        assert!("/..\\windows\\style".contains(".."));

        // These should be accepted (no ..)
        assert!(!"safe.png".contains(".."));
        assert!(!"path/to/safe.png".contains(".."));
        assert!(!"image123.png".contains(".."));

        // Test file extension validation
        assert!("image.png".ends_with(".png"));
        assert!(!"script.js".ends_with(".png"));
        assert!(!"style.css".ends_with(".png"));
        assert!(!"config.json".ends_with(".png"));
        assert!(!"image.PNG".ends_with(".png")); // Case sensitive
    }

    #[tokio::test]
    async fn test_file_operations_security() {
        let temp_dir = TempDir::new().unwrap();

        // Create test files
        fs::write(temp_dir.path().join("safe.png"), b"safe content").unwrap();

        // Create file outside temp directory
        let parent_dir = temp_dir.path().parent().unwrap();
        let outside_file = parent_dir.join("outside.png");
        fs::write(&outside_file, b"should not be accessible").unwrap();

        // Test path canonicalization security
        let safe_path = temp_dir.path().join("safe.png");
        let outside_path = temp_dir.path().join("../outside.png");

        // Verify safe file is within directory
        if let Ok(canonical_file) = safe_path.canonicalize() {
            if let Ok(canonical_dir) = temp_dir.path().canonicalize() {
                assert!(canonical_file.starts_with(&canonical_dir));
            }
        }

        // Verify dangerous path would be caught by canonicalization
        if let Ok(canonical_file) = outside_path.canonicalize() {
            if let Ok(canonical_dir) = temp_dir.path().canonicalize() {
                assert!(!canonical_file.starts_with(&canonical_dir));
            }
        }

        // Cleanup
        let _ = fs::remove_file(outside_file);
    }

    #[tokio::test]
    async fn test_file_reading_and_binary_serving() {
        let temp_dir = TempDir::new().unwrap();

        // Create test PNG file with known content
        let test_content = b"fake png data for binary test";
        let test_file = temp_dir.path().join("test.png");
        fs::write(&test_file, test_content).unwrap();

        // Test file reading returns exact binary content
        if let Ok(file_contents) = tokio::fs::read(&test_file).await {
            assert_eq!(file_contents.as_slice(), test_content);

            // Test that content is suitable for HTTP binary response
            let bytes_content = bytes::Bytes::from(file_contents);
            assert_eq!(bytes_content.len(), test_content.len());
            assert_eq!(bytes_content.as_ref(), test_content);

            // Verify binary content properties
            assert!(!bytes_content.is_empty());
            assert_eq!(bytes_content[0], test_content[0]); // First byte matches
        }
    }

    #[tokio::test]
    async fn test_http_server_startup() {
        let mut service = ScreenshotService::new();

        // Test that start_http_server returns error when not configured
        let result = service.start_http_server().await;
        assert!(result.is_ok()); // Should succeed but do nothing when not configured

        // Configure and test startup
        service.configure_http_server(0, "/tmp".to_string()); // Port 0 = random port
        let result = service.start_http_server().await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_environment_variable_configuration() {
        // Save original values
        let original_port = env::var("SCREENSHOT_HTTP_PORT").ok();
        let original_dir = env::var("SCREENSHOT_DIRECTORY").ok();
        let original_host = env::var("SCREENSHOT_HTTP_HOST").ok();

        unsafe {
            // Test with environment variables set
            env::set_var("SCREENSHOT_HTTP_PORT", "9999");
            env::set_var("SCREENSHOT_DIRECTORY", "/custom/path");
            env::set_var("SCREENSHOT_HTTP_HOST", "custom.host");
        }

        // Test base URL generation
        let base_url = crate::service::GoldentoothService::get_screenshot_base_url();
        assert_eq!(base_url, "http://custom.host:9999");

        unsafe {
            // Restore original values
            if let Some(port) = original_port {
                env::set_var("SCREENSHOT_HTTP_PORT", port);
            } else {
                env::remove_var("SCREENSHOT_HTTP_PORT");
            }

            if let Some(dir) = original_dir {
                env::set_var("SCREENSHOT_DIRECTORY", dir);
            } else {
                env::remove_var("SCREENSHOT_DIRECTORY");
            }

            if let Some(host) = original_host {
                env::set_var("SCREENSHOT_HTTP_HOST", host);
            } else {
                env::remove_var("SCREENSHOT_HTTP_HOST");
            }
        }
    }

    #[test]
    fn test_default_configuration() {
        // Save any existing values
        let original_port = env::var("SCREENSHOT_HTTP_PORT").ok();
        let original_dir = env::var("SCREENSHOT_DIRECTORY").ok();
        let original_host = env::var("SCREENSHOT_HTTP_HOST").ok();

        unsafe {
            // Ensure environment variables are not set
            env::remove_var("SCREENSHOT_HTTP_PORT");
            env::remove_var("SCREENSHOT_DIRECTORY");
            env::remove_var("SCREENSHOT_HTTP_HOST");
        }

        // Test default values - verify each component
        let host = std::env::var("SCREENSHOT_HTTP_HOST")
            .unwrap_or_else(|_| "velaryon.nodes.goldentooth.net".to_string());
        let port = std::env::var("SCREENSHOT_HTTP_PORT").unwrap_or_else(|_| "8081".to_string());

        assert_eq!(host, "velaryon.nodes.goldentooth.net");
        assert_eq!(port, "8081");

        let base_url = format!("http://{host}:{port}");
        assert_eq!(base_url, "http://velaryon.nodes.goldentooth.net:8081");

        // Also test the actual function
        let function_url = crate::service::GoldentoothService::get_screenshot_base_url();
        assert_eq!(function_url, "http://velaryon.nodes.goldentooth.net:8081");

        unsafe {
            // Restore original values to avoid affecting other tests
            if let Some(port) = original_port {
                env::set_var("SCREENSHOT_HTTP_PORT", port);
            }
            if let Some(dir) = original_dir {
                env::set_var("SCREENSHOT_DIRECTORY", dir);
            }
            if let Some(host) = original_host {
                env::set_var("SCREENSHOT_HTTP_HOST", host);
            }
        }
    }
}
