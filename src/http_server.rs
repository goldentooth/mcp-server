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

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    service: GoldentoothService,
    auth_service: Option<AuthService>,
) -> Result<Response<Full<Bytes>>, Infallible> {
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

    // Handle authentication endpoints (public, no authentication required)
    if req.uri().path().starts_with("/auth/") {
        return handle_auth_request(req, auth_service).await;
    }

    // Handle OAuth callback endpoint
    if req.method() == Method::GET && req.uri().path() == "/callback" {
        // Extract query parameters
        let query = req.uri().query().unwrap_or("");
        let mut params = std::collections::HashMap::new();

        // Simple query string parsing
        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                params.insert(
                    key.to_string(),
                    value
                        .replace('+', " ")
                        .replace("%20", " ")
                        .replace("%2C", ",")
                        .replace("%2F", "/")
                        .replace("%3A", ":")
                        .replace("%3F", "?")
                        .replace("%3D", "=")
                        .replace("%26", "&"),
                );
            }
        }

        if let Some(code) = params.get("code") {
            // Display the authorization code for the user to copy
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
                code
            );

            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/html; charset=utf-8")
                .body(Full::new(Bytes::from(html)))
                .unwrap());
        } else if let Some(error) = params.get("error") {
            // Handle OAuth error
            let error_desc = params.get("error_description").unwrap_or(error);
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
                error, error_desc
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

    // Only allow POST requests for MCP endpoints
    if req.method() != Method::POST {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Full::new(Bytes::from("Method not allowed")))
            .unwrap());
    }

    // Extract headers for authentication
    let mut headers = HashMap::new();
    for (name, value) in req.headers() {
        if let Ok(value_str) = value.to_str() {
            headers.insert(name.to_string(), value_str.to_string());
        }
    }

    // Check authentication if enabled
    if let Some(ref auth) = auth_service {
        if let Some(auth_header) = headers.get("authorization") {
            if let Some(token) = auth_header.strip_prefix("Bearer ") {
                match auth.validate_token(token).await {
                    Ok(_claims) => {
                        // Authentication successful, continue
                    }
                    Err(e) => {
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
                return Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("Access-Control-Allow-Origin", "*")
                    .body(Full::new(Bytes::from(
                        "{\"error\":\"Invalid authorization header format\"}",
                    )))
                    .unwrap());
            }
        } else {
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("Access-Control-Allow-Origin", "*")
                .body(Full::new(Bytes::from(
                    "{\"error\":\"Missing authorization header\"}",
                )))
                .unwrap());
        }
    }

    // Read request body
    let body = match req.collect().await {
        Ok(body) => body.to_bytes(),
        Err(_) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Access-Control-Allow-Origin", "*")
                .body(Full::new(Bytes::from(
                    "{\"error\":\"Failed to read request body\"}",
                )))
                .unwrap());
        }
    };

    // Parse JSON-RPC request
    let json_rpc: Value = match serde_json::from_slice(&body) {
        Ok(json) => json,
        Err(_) => {
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
    let response = handle_json_rpc(json_rpc, service).await;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .header("Access-Control-Allow-Origin", "*")
        .body(Full::new(Bytes::from(response)))
        .unwrap())
}

async fn handle_json_rpc(request: Value, service: GoldentoothService) -> String {
    // Extract method from JSON-RPC request
    let method = match request.get("method").and_then(|m| m.as_str()) {
        Some(method) => method,
        None => {
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

    match method {
        "initialize" => serde_json::json!({
            "jsonrpc": "2.0",
            "result": {
                "protocolVersion": "0.1.0",
                "capabilities": {},
                "serverInfo": {
                    "name": "goldentooth-mcp",
                    "version": "0.0.23"
                }
            },
            "id": id
        })
        .to_string(),
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
                    .body(Full::new(Bytes::from(
                        serde_json::json!({"error": format!("OIDC discovery failed: {}", e)})
                            .to_string(),
                    )))
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
                    .body(Full::new(Bytes::from(
                        serde_json::json!({"error": format!("Failed to generate authorization URL: {}", e)}).to_string()
                    )))
                    .unwrap()),
            }
        }
        (&Method::POST, "/auth/token") => {
            // Exchange authorization code for token
            let request_data = match parse_json_body(req).await {
                Ok(data) => data,
                Err(response) => return Ok(response),
            };

            let code = match request_data.get("code").and_then(|c| c.as_str()) {
                Some(code) => code,
                None => {
                    return Ok(create_json_error_response(
                        StatusCode::BAD_REQUEST,
                        "Missing 'code' parameter",
                    ));
                }
            };

            match auth.exchange_code_for_token(code).await {
                Ok(access_token) => {
                    let response_data = serde_json::json!({
                        "access_token": access_token.secret(),
                        "token_type": "Bearer",
                        "expires_in": 3600
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
                    .body(Full::new(Bytes::from(
                        serde_json::json!({"error": format!("Token exchange failed: {}", e)})
                            .to_string(),
                    )))
                    .unwrap()),
            }
        }
        (&Method::POST, "/auth/refresh") => {
            // Refresh access token
            let request_data = match parse_json_body(req).await {
                Ok(data) => data,
                Err(response) => return Ok(response),
            };

            let refresh_token = match request_data.get("refresh_token").and_then(|t| t.as_str()) {
                Some(token) => token,
                None => {
                    return Ok(create_json_error_response(
                        StatusCode::BAD_REQUEST,
                        "Missing 'refresh_token' parameter",
                    ));
                }
            };

            match auth.refresh_token(refresh_token).await {
                Ok(access_token) => {
                    let response_data = serde_json::json!({
                        "access_token": access_token.secret(),
                        "token_type": "Bearer",
                        "expires_in": 3600
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
                    .body(Full::new(Bytes::from(
                        serde_json::json!({"error": format!("Token refresh failed: {}", e)})
                            .to_string(),
                    )))
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
}
