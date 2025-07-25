use crate::auth::AuthService;
use crate::service::GoldentoothService;
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode, body::Bytes, server::conn::http1, service::service_fn,
};
use hyper_util::rt::TokioIo;
use rmcp::Service;
use serde_json::Value;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use tokio::net::TcpListener;

// OAuth well-known endpoint constants
const OAUTH_WELL_KNOWN_PATH: &str = "/.well-known/oauth-authorization-server";
const OIDC_WELL_KNOWN_PATH: &str = "/.well-known/openid-configuration";

pub struct HttpServer {
    service: GoldentoothService,
    auth_service: Option<AuthService>,
}

impl HttpServer {
    pub fn new(service: GoldentoothService, auth_service: Option<AuthService>) -> Self {
        Self {
            service,
            auth_service,
        }
    }

    pub async fn serve(self, addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(addr).await?;
        println!("MCP HTTP server listening on {}", addr);

        loop {
            let (stream, _) = listener.accept().await?;
            let io = TokioIo::new(stream);
            let service = self.service.clone();
            let auth_service = self.auth_service.clone();

            tokio::task::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req| {
                            handle_request(req, service.clone(), auth_service.clone())
                        }),
                    )
                    .await
                {
                    eprintln!("Error serving connection: {:?}", err);
                }
            });
        }
    }

    // Helper method for testing - handles a single request without network
    pub async fn handle_request_for_test(
        &self,
        _method: &str,
        body: &str,
        auth_header: Option<&str>,
    ) -> Result<String, String> {
        let mut headers = HashMap::new();
        if let Some(auth) = auth_header {
            headers.insert("authorization".to_string(), auth.to_string());
        }

        // Parse JSON-RPC request
        let json_rpc: Value =
            serde_json::from_str(body).map_err(|_| "Invalid JSON in request body".to_string())?;

        // Check authentication if enabled
        if let Some(ref auth) = self.auth_service {
            if let Some(auth_header) = headers.get("authorization") {
                if let Some(token) = auth_header.strip_prefix("Bearer ") {
                    match auth.validate_token(token).await {
                        Ok(_claims) => {
                            // Authentication successful, continue
                        }
                        Err(e) => {
                            return Err(format!("Authentication failed: {}", e));
                        }
                    }
                } else {
                    return Err("Invalid authorization header format".to_string());
                }
            } else {
                return Err("Missing authorization header".to_string());
            }
        }

        // Handle the JSON-RPC request
        Ok(handle_json_rpc(json_rpc, self.service.clone()).await)
    }
}

pub async fn handle_request(
    req: Request<hyper::body::Incoming>,
    service: GoldentoothService,
    auth_service: Option<AuthService>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // Log all incoming requests for debugging
    println!(
        "🌐 HTTP: {} {} - Headers: {:?}",
        req.method(),
        req.uri(),
        req.headers()
            .iter()
            .map(|(k, v)| format!("{}: {:?}", k, v))
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Handle CORS preflight
    if req.method() == Method::OPTIONS {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            .header(
                "Access-Control-Allow-Headers",
                "Content-Type, Authorization",
            )
            .body(Full::new(Bytes::new()))
            .unwrap());
    }

    // Handle health check endpoint
    if req.method() == Method::GET && req.uri().path() == "/health" {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .header("Access-Control-Allow-Origin", "*")
            .body(Full::new(Bytes::from(
                r#"{"status":"healthy","service":"goldentooth-mcp"}"#,
            )))
            .unwrap());
    }

    // Handle OAuth well-known endpoints (public, no authentication required)
    // Support GET, HEAD, and POST methods (some clients may use POST for discovery)
    if (req.uri().path() == OAUTH_WELL_KNOWN_PATH || req.uri().path() == OIDC_WELL_KNOWN_PATH)
        && (req.method() == Method::GET
            || req.method() == Method::HEAD
            || req.method() == Method::POST)
    {
        println!(
            "🔍 HTTP: Handling OAuth metadata request: {} {}",
            req.method(),
            req.uri().path()
        );
        return handle_oauth_metadata(auth_service, req.method()).await;
    }

    // Handle authentication endpoints (public, no authentication required)
    if req.uri().path().starts_with("/auth/") {
        return handle_auth_request(req, auth_service).await;
    }

    // Handle OAuth callback endpoint
    if req.method() == Method::GET && req.uri().path() == "/callback" {
        // Extract query parameters
        let query = req.uri().query().unwrap_or("");
        let mut params = std::collections::HashMap::new();

        // Proper query string parsing with URL decoding
        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                let decoded_key = urlencoding::decode(key).unwrap_or_else(|_| key.into());
                let decoded_value = urlencoding::decode(value).unwrap_or_else(|_| value.into());
                params.insert(decoded_key.to_string(), decoded_value.to_string());
            }
        }

        if let Some(code) = params.get("code") {
            // Display the authorization code for the user to copy (HTML-escaped for security)
            let escaped_code = html_escape(code);
            let html = format!(
                r#"<!DOCTYPE html>
<html>
<head>
    <title>MCP Authorization</title>
    <style>
        body {{ font-family: sans-serif; margin: 40px; }}
        .code-container {{
            background: #f0f0f0;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }}
        code {{
            font-size: 14px;
            word-break: break-all;
            display: block;
            padding: 10px;
            background: white;
            border: 1px solid #ddd;
            border-radius: 4px;
        }}
        .instructions {{ margin-top: 20px; }}
    </style>
</head>
<body>
    <h1>Authorization Successful</h1>
    <p>Copy the authorization code below:</p>
    <div class="code-container">
        <code id="auth-code">{}</code>
    </div>
    <div class="instructions">
        <p>Paste this code back into the goldentooth mcp_auth command when prompted.</p>
    </div>
    <script>
        // Auto-select the code for easy copying
        window.onload = function() {{
            const codeElement = document.getElementById('auth-code');
            const range = document.createRange();
            range.selectNode(codeElement);
            window.getSelection().removeAllRanges();
            window.getSelection().addRange(range);
        }};
    </script>
</body>
</html>"#,
                escaped_code
            );

            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/html; charset=utf-8")
                .body(Full::new(Bytes::from(html)))
                .unwrap());
        } else if let Some(error) = params.get("error") {
            // Handle OAuth error (HTML-escaped for security)
            let error_desc = params.get("error_description").unwrap_or(error);
            let escaped_error = html_escape(error);
            let escaped_error_desc = html_escape(error_desc);
            let html = format!(
                r#"<!DOCTYPE html>
<html>
<head>
    <title>Authorization Error</title>
    <style>
        body {{ font-family: sans-serif; margin: 40px; }}
        .error {{
            background: #fee;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #fcc;
        }}
    </style>
</head>
<body>
    <h1>Authorization Failed</h1>
    <div class="error">
        <p><strong>Error:</strong> {}</p>
        <p>{}</p>
    </div>
    <p><a href="/">Try again</a></p>
</body>
</html>"#,
                escaped_error, escaped_error_desc
            );

            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/html; charset=utf-8")
                .body(Full::new(Bytes::from(html)))
                .unwrap());
        } else {
            // No code or error parameter
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Content-Type", "text/plain")
                .body(Full::new(Bytes::from(
                    "Missing authorization code or error parameter",
                )))
                .unwrap());
        }
    }

    // Handle MCP JSON-RPC requests (only for /mcp/request path)
    if req.method() == Method::POST && req.uri().path() == "/mcp/request" {
        println!("🎯 MCP: Received MCP request to {}", req.uri().path());
        // Continue with MCP request handling
    } else {
        // Return 404 for all other unhandled paths
        println!(
            "🚫 HTTP: Unknown path {} {} - returning 404",
            req.method(),
            req.uri().path()
        );
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "application/json")
            .header("Access-Control-Allow-Origin", "*")
            .body(Full::new(Bytes::from(
                "{\"error\":\"Not Found\",\"message\":\"The requested path was not found\"}",
            )))
            .unwrap());
    }

    // Extract headers for authentication first (before consuming req)
    let mut headers = HashMap::new();
    for (name, value) in req.headers() {
        if let Ok(value_str) = value.to_str() {
            headers.insert(name.to_string(), value_str.to_string());
        }
    }

    // Read request body to determine if this is an initialize request
    let body = match req.collect().await {
        Ok(body) => body.to_bytes(),
        Err(e) => {
            println!("❌ HTTP: Failed to read request body: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Access-Control-Allow-Origin", "*")
                .body(Full::new(Bytes::from(
                    "{\"error\":\"Failed to read request body\"}",
                )))
                .unwrap());
        }
    };

    // Parse JSON to check if this is an initialize request
    let is_initialize_request = if let Ok(json) = serde_json::from_slice::<Value>(&body) {
        json.get("method")
            .and_then(|m| m.as_str())
            .map(|method| method == "initialize")
            .unwrap_or(false)
    } else {
        false
    };

    println!("🔍 MCP: Is initialize request: {}", is_initialize_request);

    println!(
        "🔐 AUTH: Extracted headers: {:?}",
        headers.keys().collect::<Vec<_>>()
    );

    // Check authentication if enabled, but skip for initialize requests
    if let Some(ref auth) = auth_service {
        if !is_initialize_request {
            println!("🔒 AUTH: Authentication service enabled, checking headers...");
            if let Some(auth_header) = headers.get("authorization") {
                println!(
                    "🔑 AUTH: Found authorization header: {}...",
                    if auth_header.len() > 20 {
                        &auth_header[..20]
                    } else {
                        auth_header
                    }
                );
                if let Some(token) = auth_header.strip_prefix("Bearer ") {
                    println!("🎫 AUTH: Extracted Bearer token (length: {})", token.len());
                    match auth.validate_token(token).await {
                        Ok(claims) => {
                            println!(
                                "✅ AUTH: Token validation successful for user: {}",
                                claims.sub
                            );
                            // Authentication successful, continue
                        }
                        Err(e) => {
                            println!("❌ AUTH: Token validation failed: {}", e);
                            eprintln!("Authentication failed: {}", e);
                            return Ok(Response::builder()
                                .status(StatusCode::UNAUTHORIZED)
                                .header("Access-Control-Allow-Origin", "*")
                                .body(Full::new(Bytes::from(format!(
                                    "{{\"error\":\"Authentication failed: {}\"}}",
                                    e
                                ))))
                                .unwrap());
                        }
                    }
                } else {
                    println!("❌ AUTH: Authorization header missing 'Bearer ' prefix");
                    return Ok(Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .header("Access-Control-Allow-Origin", "*")
                        .body(Full::new(Bytes::from(
                            "{\"error\":\"Invalid authorization header format\"}",
                        )))
                        .unwrap());
                }
            } else {
                println!("❌ AUTH: No authorization header found in request");
                return Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("Access-Control-Allow-Origin", "*")
                    .body(Full::new(Bytes::from(
                        "{\"error\":\"Missing authorization header\"}",
                    )))
                    .unwrap());
            }
        } else {
            println!("🚀 AUTH: Skipping authentication for initialize request");
        }
    } else {
        println!("🔓 AUTH: No authentication service configured, proceeding without auth");
    }

    // Body is already read above

    let body_str = String::from_utf8_lossy(&body);
    println!(
        "📨 MCP: Request body (length: {}): {}",
        body.len(),
        if body_str.len() > 200 {
            format!("{}...", &body_str[..200])
        } else {
            body_str.to_string()
        }
    );

    // Parse JSON-RPC request
    let json_rpc: Value = match serde_json::from_slice::<Value>(&body) {
        Ok(json) => {
            println!("✅ JSON: Successfully parsed JSON-RPC request");
            if let Some(method) = json.get("method").and_then(|m| m.as_str()) {
                println!("🔧 MCP: Method: {}", method);
                if method == "initialize" {
                    println!("🚀 MCP: INITIALIZE REQUEST DETECTED!");
                    if let Some(params) = json.get("params") {
                        println!(
                            "📋 MCP: Initialize params: {}",
                            serde_json::to_string_pretty(params)
                                .unwrap_or_else(|_| "failed to serialize".to_string())
                        );
                    }
                }
            }
            json
        }
        Err(e) => {
            println!("❌ JSON: Invalid JSON in request body: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Access-Control-Allow-Origin", "*")
                .body(Full::new(Bytes::from(
                    "{\"error\":\"Invalid JSON in request body\"}",
                )))
                .unwrap());
        }
    };

    // Handle the JSON-RPC request
    println!("📤 MCP: Forwarding request to handle_json_rpc...");
    let response = handle_json_rpc(json_rpc, service).await;
    println!(
        "📥 MCP: Response from handle_json_rpc: {}",
        if response.len() > 300 {
            format!("{}... (truncated)", &response[..300])
        } else {
            response.clone()
        }
    );

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .header("Access-Control-Allow-Origin", "*")
        .body(Full::new(Bytes::from(response)))
        .unwrap())
}

async fn handle_json_rpc(request: Value, service: GoldentoothService) -> String {
    println!(
        "🔍 JSON-RPC: Processing request: {}",
        serde_json::to_string_pretty(&request)
            .unwrap_or_else(|_| "failed to serialize".to_string())
    );

    // Extract method from JSON-RPC request
    let method = match request.get("method").and_then(|m| m.as_str()) {
        Some(method) => {
            println!("📍 JSON-RPC: Method extracted: {}", method);
            method
        }
        None => {
            println!("❌ JSON-RPC: No method found in request");
            return serde_json::json!({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32600,
                    "message": "Invalid Request"
                },
                "id": request.get("id")
            })
            .to_string();
        }
    };

    let id = request.get("id");
    println!("🆔 JSON-RPC: Request ID: {:?}", id);

    match method {
        "initialize" => {
            println!("🚀 JSON-RPC: Processing INITIALIZE method");
            let info = service.get_info();
            println!("📊 CAPABILITIES: Getting server info...");
            println!("📊 CAPABILITIES: Server name: {}", info.server_info.name);
            println!(
                "📊 CAPABILITIES: Server version: {}",
                info.server_info.version
            );
            println!(
                "📊 CAPABILITIES: Protocol version: {:?}",
                info.protocol_version
            );
            println!(
                "📊 CAPABILITIES: Has tools capability: {}",
                info.capabilities.tools.is_some()
            );
            if let Some(ref tools_cap) = info.capabilities.tools {
                println!("📊 CAPABILITIES: Tools capability details: {:?}", tools_cap);
            }
            println!("📊 CAPABILITIES: Instructions: {:?}", info.instructions);

            // Extract the version string from ProtocolVersion("2024-11-05") format
            let version_str = format!("{:?}", info.protocol_version);
            let protocol_version = version_str
                .strip_prefix("ProtocolVersion(\"")
                .and_then(|s| s.strip_suffix("\")"))
                .unwrap_or("2024-11-05"); // fallback to current spec version

            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "result": {
                    "protocolVersion": protocol_version,
                    "capabilities": info.capabilities,
                    "serverInfo": {
                        "name": info.server_info.name,
                        "version": info.server_info.version
                    }
                },
                "id": id
            });

            println!(
                "✅ INITIALIZE: Generated response: {}",
                serde_json::to_string_pretty(&response)
                    .unwrap_or_else(|_| "failed to serialize".to_string())
            );
            response.to_string()
        }
        "server/get_info" => {
            let info = service.get_info();
            serde_json::json!({
                "jsonrpc": "2.0",
                "result": {
                    "name": info.server_info.name,
                    "version": info.server_info.version,
                    "capabilities": info.capabilities
                },
                "id": id
            })
            .to_string()
        }
        "tools/list" => serde_json::json!({
            "jsonrpc": "2.0",
            "result": {
                "tools": []
            },
            "id": id
        })
        .to_string(),
        _ => serde_json::json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -32601,
                "message": "Method not found"
            },
            "id": id
        })
        .to_string(),
    }
}

#[allow(dead_code)]
fn create_json_error_response(status: StatusCode, error_message: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("Access-Control-Allow-Origin", "*")
        .body(Full::new(Bytes::from(
            serde_json::json!({"error": error_message}).to_string(),
        )))
        .unwrap()
}

pub fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

#[allow(dead_code)]
async fn parse_json_body(
    req: Request<hyper::body::Incoming>,
) -> Result<serde_json::Value, Response<Full<Bytes>>> {
    let body = match req.collect().await {
        Ok(body) => body.to_bytes(),
        Err(_) => {
            return Err(create_json_error_response(
                StatusCode::BAD_REQUEST,
                "Failed to read request body",
            ));
        }
    };

    let request_data: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(data) => data,
        Err(_) => {
            return Err(create_json_error_response(
                StatusCode::BAD_REQUEST,
                "Invalid JSON in request body",
            ));
        }
    };

    Ok(request_data)
}

async fn handle_oauth_metadata(
    auth_service: Option<AuthService>,
    method: &Method,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let auth = match auth_service {
        Some(auth) => auth,
        None => {
            let response_body = if method == Method::HEAD {
                Full::new(Bytes::new())
            } else {
                Full::new(Bytes::from(
                    serde_json::json!({"error": "OAuth not configured"}).to_string(),
                ))
            };

            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("Content-Type", "application/json")
                .header("Access-Control-Allow-Origin", "*")
                .body(response_body)
                .unwrap());
        }
    };

    // Get OIDC discovery config and map to OAuth metadata format
    match auth.discover_oidc_config().await {
        Ok(discovery) => {
            // OAuth 2.0 Authorization Server Metadata (RFC 8414)
            let metadata = serde_json::json!({
                "issuer": discovery.issuer,
                "authorization_endpoint": discovery.authorization_endpoint,
                "token_endpoint": discovery.token_endpoint,
                "jwks_uri": discovery.jwks_uri,
                "response_types_supported": discovery.response_types_supported,
                "grant_types_supported": discovery.grant_types_supported,
                "scopes_supported": discovery.scopes_supported,
                "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
                "code_challenge_methods_supported": ["S256", "plain"],
                "service_documentation": "https://docs.goldentooth.net/mcp",
            });

            // HEAD requests should return empty body with same headers
            let response_body = if method == Method::HEAD {
                Full::new(Bytes::new())
            } else {
                Full::new(Bytes::from(metadata.to_string()))
            };

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .header("Access-Control-Allow-Origin", "*")
                .body(response_body)
                .unwrap())
        }
        Err(e) => {
            use crate::auth::AuthError;
            let error_message = match e {
                AuthError::DiscoveryFailed(_) => {
                    r#"{"error":"OAuth discovery service unavailable"}"#
                }
                _ => r#"{"error":"OAuth metadata temporarily unavailable"}"#,
            };

            let response_body = if method == Method::HEAD {
                Full::new(Bytes::new())
            } else {
                Full::new(Bytes::from(error_message))
            };

            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/json")
                .header("Access-Control-Allow-Origin", "*")
                .body(response_body)
                .unwrap())
        }
    }
}

async fn handle_auth_request(
    req: Request<hyper::body::Incoming>,
    auth_service: Option<AuthService>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let auth = match auth_service {
        Some(auth) => auth,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header("Content-Type", "application/json")
                .header("Access-Control-Allow-Origin", "*")
                .body(Full::new(Bytes::from(
                    serde_json::json!({"error": "Authentication not configured"}).to_string(),
                )))
                .unwrap());
        }
    };

    let path = req.uri().path();
    let method = req.method();

    match (method, path) {
        (&Method::GET, "/auth/info") => {
            // Return OIDC discovery info
            match auth.discover_oidc_config().await {
                Ok(discovery) => Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .header("Access-Control-Allow-Origin", "*")
                    .body(Full::new(Bytes::from(
                        serde_json::to_string(&discovery).unwrap(),
                    )))
                    .unwrap()),
                Err(e) => Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header("Content-Type", "application/json")
                    .header("Access-Control-Allow-Origin", "*")
                    .body(Full::new(Bytes::from(format!(
                        r#"{{"error":"OIDC discovery failed: {}"}}"#,
                        e
                    ))))
                    .unwrap()),
            }
        }
        (&Method::POST, "/auth/authorize") => {
            // Return authorization URL
            match auth.get_authorization_url() {
                Ok((auth_url, _csrf_token)) => {
                    let response_data = serde_json::json!({
                        "authorization_url": auth_url
                    });
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/json")
                        .header("Access-Control-Allow-Origin", "*")
                        .body(Full::new(Bytes::from(response_data.to_string())))
                        .unwrap())
                }
                Err(e) => Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header("Content-Type", "application/json")
                    .header("Access-Control-Allow-Origin", "*")
                    .body(Full::new(Bytes::from(format!(
                        r#"{{"error":"Failed to generate authorization URL: {}"}}"#,
                        e
                    ))))
                    .unwrap()),
            }
        }
        (&Method::POST, "/auth/token") => {
            // Exchange authorization code for token
            let body = match req.collect().await {
                Ok(body) => body.to_bytes(),
                Err(_) => {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .header("Content-Type", "application/json")
                        .header("Access-Control-Allow-Origin", "*")
                        .body(Full::new(Bytes::from(
                            r#"{"error":"Failed to read request body"}"#,
                        )))
                        .unwrap());
                }
            };

            let request_data: serde_json::Value = match serde_json::from_slice(&body) {
                Ok(data) => data,
                Err(_) => {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .header("Content-Type", "application/json")
                        .header("Access-Control-Allow-Origin", "*")
                        .body(Full::new(Bytes::from(
                            r#"{"error":"Invalid JSON in request body"}"#,
                        )))
                        .unwrap());
                }
            };

            let code = match request_data.get("code").and_then(|c| c.as_str()) {
                Some(code) => code,
                None => {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .header("Content-Type", "application/json")
                        .header("Access-Control-Allow-Origin", "*")
                        .body(Full::new(Bytes::from(
                            r#"{"error":"Missing 'code' parameter"}"#,
                        )))
                        .unwrap());
                }
            };

            let code_preview = if code.len() > 40 {
                format!("{}...{}", &code[..20], &code[code.len() - 20..])
            } else {
                code.to_string()
            };
            println!(
                "🔄 HTTP: Processing token exchange request with code: {}",
                code_preview
            );

            match auth.exchange_code_for_token(code).await {
                Ok(access_token) => {
                    println!("✅ HTTP: Token exchange successful, returning access token");
                    let response_data = serde_json::json!({
                        "access_token": access_token.secret(),
                        "token_type": "Bearer",
                        "expires_in": 2592000  // 30 days in seconds
                    });
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/json")
                        .header("Access-Control-Allow-Origin", "*")
                        .body(Full::new(Bytes::from(response_data.to_string())))
                        .unwrap())
                }
                Err(e) => {
                    println!(
                        "❌ HTTP: Token exchange failed with detailed error: {:?}",
                        e
                    );
                    Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .header("Content-Type", "application/json")
                        .header("Access-Control-Allow-Origin", "*")
                        .body(Full::new(Bytes::from(format!(
                            r#"{{"error":"DETAILED_ERROR: {}"}}"#,
                            e
                        ))))
                        .unwrap())
                }
            }
        }
        (&Method::POST, "/auth/refresh") => {
            // Refresh access token
            let body = match req.collect().await {
                Ok(body) => body.to_bytes(),
                Err(_) => {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .header("Content-Type", "application/json")
                        .header("Access-Control-Allow-Origin", "*")
                        .body(Full::new(Bytes::from(
                            r#"{"error":"Failed to read request body"}"#,
                        )))
                        .unwrap());
                }
            };

            let request_data: serde_json::Value = match serde_json::from_slice(&body) {
                Ok(data) => data,
                Err(_) => {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .header("Content-Type", "application/json")
                        .header("Access-Control-Allow-Origin", "*")
                        .body(Full::new(Bytes::from(
                            r#"{"error":"Invalid JSON in request body"}"#,
                        )))
                        .unwrap());
                }
            };

            let refresh_token = match request_data.get("refresh_token").and_then(|t| t.as_str()) {
                Some(token) => token,
                None => {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .header("Content-Type", "application/json")
                        .header("Access-Control-Allow-Origin", "*")
                        .body(Full::new(Bytes::from(
                            r#"{"error":"Missing 'refresh_token' parameter"}"#,
                        )))
                        .unwrap());
                }
            };

            match auth.refresh_token(refresh_token).await {
                Ok(access_token) => {
                    let response_data = serde_json::json!({
                        "access_token": access_token.secret(),
                        "token_type": "Bearer",
                        "expires_in": 2592000  // 30 days in seconds
                    });
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/json")
                        .header("Access-Control-Allow-Origin", "*")
                        .body(Full::new(Bytes::from(response_data.to_string())))
                        .unwrap())
                }
                Err(e) => Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header("Content-Type", "application/json")
                    .header("Access-Control-Allow-Origin", "*")
                    .body(Full::new(Bytes::from(format!(
                        r#"{{"error":"Token refresh failed: {}"}}"#,
                        e
                    ))))
                    .unwrap()),
            }
        }
        _ => {
            // Unknown auth endpoint
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("Content-Type", "application/json")
                .header("Access-Control-Allow-Origin", "*")
                .body(Full::new(Bytes::from(
                    serde_json::json!({"error": "Auth endpoint not found"}).to_string(),
                )))
                .unwrap())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_http_server_initialize() {
        let service = GoldentoothService::new();
        let server = HttpServer::new(service, None);

        let request = r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"0.1.0","capabilities":{}},"id":1}"#;
        let response = server
            .handle_request_for_test("initialize", request, None)
            .await
            .unwrap();

        let json: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["id"], 1);
        assert_eq!(json["result"]["serverInfo"]["name"], "goldentooth-mcp");
        assert_eq!(json["result"]["serverInfo"]["version"], "0.0.23");
    }

    #[tokio::test]
    async fn test_http_server_get_info() {
        let service = GoldentoothService::new();
        let server = HttpServer::new(service, None);

        let request = r#"{"jsonrpc":"2.0","method":"server/get_info","id":2}"#;
        let response = server
            .handle_request_for_test("server/get_info", request, None)
            .await
            .unwrap();

        let json: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["id"], 2);
        assert_eq!(json["result"]["name"], "goldentooth-mcp");
        assert_eq!(json["result"]["version"], env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn test_http_server_tools_list() {
        let service = GoldentoothService::new();
        let server = HttpServer::new(service, None);

        let request = r#"{"jsonrpc":"2.0","method":"tools/list","id":3}"#;
        let response = server
            .handle_request_for_test("tools/list", request, None)
            .await
            .unwrap();

        let json: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["id"], 3);
        assert_eq!(json["result"]["tools"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn test_http_server_unknown_method() {
        let service = GoldentoothService::new();
        let server = HttpServer::new(service, None);

        let request = r#"{"jsonrpc":"2.0","method":"unknown/method","id":4}"#;
        let response = server
            .handle_request_for_test("unknown/method", request, None)
            .await
            .unwrap();

        let json: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["id"], 4);
        assert_eq!(json["error"]["code"], -32601);
        assert_eq!(json["error"]["message"], "Method not found");
    }

    #[tokio::test]
    async fn test_http_server_invalid_json() {
        let service = GoldentoothService::new();
        let server = HttpServer::new(service, None);

        let request = r#"{"invalid":"json"#;
        let response = server
            .handle_request_for_test("invalid", request, None)
            .await;

        assert!(response.is_err());
        assert_eq!(response.unwrap_err(), "Invalid JSON in request body");
    }

    #[tokio::test]
    async fn test_http_server_missing_method() {
        let service = GoldentoothService::new();
        let server = HttpServer::new(service, None);

        let request = r#"{"jsonrpc":"2.0","id":5}"#;
        let response = server
            .handle_request_for_test("missing", request, None)
            .await
            .unwrap();

        let json: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["id"], 5);
        assert_eq!(json["error"]["code"], -32600);
        assert_eq!(json["error"]["message"], "Invalid Request");
    }

    #[test]
    fn test_health_endpoint_format() {
        // Test that health endpoint returns proper JSON
        let health_response = r#"{"status":"healthy","service":"goldentooth-mcp"}"#;
        let json: Value = serde_json::from_str(health_response).unwrap();
        assert_eq!(json["status"], "healthy");
        assert_eq!(json["service"], "goldentooth-mcp");
    }

    #[test]
    fn test_create_json_error_response() {
        // Test that the helper function creates proper JSON error responses
        let response = create_json_error_response(StatusCode::BAD_REQUEST, "Test error message");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Verify headers are set correctly
        assert_eq!(
            response.headers().get("Content-Type").unwrap(),
            "application/json"
        );
        assert_eq!(
            response
                .headers()
                .get("Access-Control-Allow-Origin")
                .unwrap(),
            "*"
        );
    }

    #[test]
    fn test_html_escape() {
        // Test HTML escaping function
        assert_eq!(html_escape("normal text"), "normal text");
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("A & B"), "A &amp; B");
        assert_eq!(html_escape("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(html_escape("'single'"), "&#x27;single&#x27;");
        assert_eq!(
            html_escape("<script>alert('XSS')</script>"),
            "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;"
        );
    }

    #[tokio::test]
    async fn test_oauth_metadata_no_auth_service() {
        // Test that metadata endpoint returns 404 when auth not configured
        let result = handle_oauth_metadata(None, &Method::GET).await.unwrap();
        assert_eq!(result.status(), StatusCode::NOT_FOUND);

        // Check headers
        assert_eq!(
            result.headers().get("Content-Type").unwrap(),
            "application/json"
        );
        assert_eq!(
            result.headers().get("Access-Control-Allow-Origin").unwrap(),
            "*"
        );
    }

    #[tokio::test]
    async fn test_oauth_metadata_head_request() {
        // Test HEAD request returns empty body with proper headers (when no auth service)
        let result = handle_oauth_metadata(None, &Method::HEAD).await.unwrap();
        assert_eq!(result.status(), StatusCode::NOT_FOUND);

        // For GET request, we get a body with error message
        let get_result = handle_oauth_metadata(None, &Method::GET).await.unwrap();
        assert_eq!(get_result.status(), StatusCode::NOT_FOUND);

        use http_body_util::BodyExt;
        let get_body_bytes = get_result.into_body().collect().await.unwrap().to_bytes();
        assert!(!get_body_bytes.is_empty()); // GET should have error message

        // HEAD should have empty body when no auth configured (error case)
        let head_body_bytes = result.into_body().collect().await.unwrap().to_bytes();
        assert!(head_body_bytes.is_empty());
    }

    #[test]
    fn test_oauth_well_known_constants() {
        // Verify the constants are set correctly
        assert_eq!(
            OAUTH_WELL_KNOWN_PATH,
            "/.well-known/oauth-authorization-server"
        );
        assert_eq!(OIDC_WELL_KNOWN_PATH, "/.well-known/openid-configuration");
    }
}
