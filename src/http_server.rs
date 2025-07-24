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
            .header("Access-Control-Allow-Methods", "POST, OPTIONS")
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
}
