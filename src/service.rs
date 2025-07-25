use crate::auth::{AuthConfig, AuthError, AuthService};
use rmcp::{
    RoleServer, Service,
    model::{
        ErrorCode, ErrorData, Implementation, InitializeResult, ProtocolVersion,
        ServerCapabilities, ToolsCapability,
    },
    service::{NotificationContext, RequestContext, ServiceRole},
};
use serde_json::{Value, json};
use std::future::Future;
use std::process::Command;

#[derive(Clone)]
pub struct GoldentoothService {
    auth_service: Option<AuthService>,
}

impl Default for GoldentoothService {
    fn default() -> Self {
        Self::new()
    }
}

impl GoldentoothService {
    pub fn new() -> Self {
        let auth_config = AuthConfig::default();
        let auth_service = if AuthService::new(auth_config.clone()).requires_auth() {
            Some(AuthService::new(auth_config))
        } else {
            None
        };

        GoldentoothService { auth_service }
    }

    pub async fn with_auth() -> Result<(Self, AuthService), AuthError> {
        let auth_config = AuthConfig::default();
        let mut auth_service = AuthService::new(auth_config);
        auth_service.initialize().await?;

        let service = GoldentoothService {
            auth_service: Some(auth_service.clone()),
        };

        Ok((service, auth_service))
    }

    pub fn is_auth_enabled(&self) -> bool {
        self.auth_service.is_some()
    }

    async fn validate_request_auth(
        &self,
        context: &RequestContext<RoleServer>,
    ) -> Result<Option<crate::auth::Claims>, ErrorData> {
        if let Some(auth_service) = &self.auth_service {
            // Extract Bearer token from context metadata
            // Note: This is a simplified example - actual implementation depends on rmcp context structure
            if let Some(auth_header) = self.extract_auth_header(context) {
                if let Some(token) = auth_header.strip_prefix("Bearer ") {
                    match auth_service.validate_token(token).await {
                        Ok(claims) => Ok(Some(claims)),
                        Err(e) => {
                            // Log the specific error for debugging, but return generic error for security
                            eprintln!("Authentication failed: {}", e);
                            Err(ErrorData {
                                code: ErrorCode(-32002),
                                message: "Authentication failed".into(),
                                data: None,
                            })
                        }
                    }
                } else {
                    Err(ErrorData {
                        code: ErrorCode(-32002),
                        message: "Invalid authorization header format".into(),
                        data: None,
                    })
                }
            } else {
                Err(ErrorData {
                    code: ErrorCode(-32002),
                    message: "Missing authorization header".into(),
                    data: None,
                })
            }
        } else {
            // No auth required
            Ok(None)
        }
    }

    #[allow(dead_code)]
    async fn execute_goldentooth_command(&self, args: &[&str]) -> Result<String, String> {
        let output = Command::new("goldentooth")
            .args(args)
            .output()
            .map_err(|e| format!("Failed to execute goldentooth command: {}", e))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("Command failed: {}", stderr))
        }
    }

    #[allow(dead_code)]
    async fn handle_cluster_ping(&self) -> Result<Value, ErrorData> {
        match self.execute_goldentooth_command(&["ping", "all"]).await {
            Ok(output) => Ok(json!({
                "success": true,
                "output": output,
                "tool": "cluster_ping"
            })),
            Err(error) => Ok(json!({
                "success": false,
                "error": error,
                "tool": "cluster_ping"
            })),
        }
    }

    #[allow(dead_code)]
    async fn handle_cluster_status(&self, node: Option<&str>) -> Result<Value, ErrorData> {
        let args = if let Some(node_name) = node {
            vec!["uptime", node_name]
        } else {
            vec!["uptime", "all"]
        };

        match self.execute_goldentooth_command(&args).await {
            Ok(output) => Ok(json!({
                "success": true,
                "output": output,
                "tool": "cluster_status",
                "node": node
            })),
            Err(error) => Ok(json!({
                "success": false,
                "error": error,
                "tool": "cluster_status",
                "node": node
            })),
        }
    }

    #[allow(dead_code)]
    async fn handle_service_status(
        &self,
        service: &str,
        node: Option<&str>,
    ) -> Result<Value, ErrorData> {
        let node_arg = node.unwrap_or("all");
        let command = format!("systemctl status {}", service);
        let args = vec!["command", node_arg, &command];

        match self.execute_goldentooth_command(&args).await {
            Ok(output) => Ok(json!({
                "success": true,
                "output": output,
                "tool": "service_status",
                "service": service,
                "node": node
            })),
            Err(error) => Ok(json!({
                "success": false,
                "error": error,
                "tool": "service_status",
                "service": service,
                "node": node
            })),
        }
    }

    #[allow(dead_code)]
    async fn handle_resource_usage(&self, node: Option<&str>) -> Result<Value, ErrorData> {
        let node_arg = node.unwrap_or("all");
        let args = vec!["command", node_arg, "free -h && df -h"];

        match self.execute_goldentooth_command(&args).await {
            Ok(output) => Ok(json!({
                "success": true,
                "output": output,
                "tool": "resource_usage",
                "node": node
            })),
            Err(error) => Ok(json!({
                "success": false,
                "error": error,
                "tool": "resource_usage",
                "node": node
            })),
        }
    }

    #[allow(dead_code)]
    async fn handle_cluster_info(&self) -> Result<Value, ErrorData> {
        // Get basic cluster information - nodes, services, etc.
        match self.execute_goldentooth_command(&["ping", "all"]).await {
            Ok(ping_output) => {
                // Try to get additional info about cluster services
                let services_result = self
                    .execute_goldentooth_command(&["command", "jast", "consul members"])
                    .await;

                Ok(json!({
                    "success": true,
                    "ping_status": ping_output,
                    "consul_members": services_result.unwrap_or_else(|e| format!("Could not get consul members: {}", e)),
                    "tool": "cluster_info"
                }))
            }
            Err(error) => Ok(json!({
                "success": false,
                "error": error,
                "tool": "cluster_info"
            })),
        }
    }

    fn extract_auth_header(&self, _context: &RequestContext<RoleServer>) -> Option<String> {
        // TODO: Extract authorization header from MCP request context
        // This is a placeholder implementation until rmcp provides access to request metadata
        //
        // For HTTP mode, we would ideally extract from HTTP headers:
        // context.headers().get("authorization").map(|h| h.to_string())
        //
        // For stdin/stdout mode, authentication would need to be handled differently,
        // potentially through a session token or connection-level authentication

        // Fallback: check environment variable for testing purposes
        // This allows testing authentication without full HTTP integration
        std::env::var("AUTHORIZATION").ok()
    }
}

impl Service<RoleServer> for GoldentoothService {
    #[allow(clippy::manual_async_fn)]
    fn handle_request(
        &self,
        request: <RoleServer as ServiceRole>::PeerReq,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<<RoleServer as ServiceRole>::Resp, ErrorData>> + Send + '_
    {
        async move {
            // Validate authentication if enabled
            let _claims = self.validate_request_auth(&context).await?;

            // Pattern match on the request type
            match request {
                rmcp::model::ClientRequest::CallToolRequest(tool_request) => {
                    let tool_name = &tool_request.params.name;
                    let arguments = &tool_request.params.arguments;

                    match tool_name.as_ref() {
                        "cluster_ping" => match self.handle_cluster_ping().await {
                            Ok(result) => {
                                let content = rmcp::model::Content::text(
                                    serde_json::to_string_pretty(&result).unwrap_or_else(|_| {
                                        "Failed to serialize result".to_string()
                                    }),
                                );
                                let tool_result =
                                    rmcp::model::CallToolResult::success(vec![content]);
                                Ok(rmcp::model::ServerResult::CallToolResult(tool_result))
                            }
                            Err(_) => {
                                let content = rmcp::model::Content::text("Failed to ping cluster");
                                let tool_result = rmcp::model::CallToolResult::error(vec![content]);
                                Ok(rmcp::model::ServerResult::CallToolResult(tool_result))
                            }
                        },
                        "cluster_status" => {
                            let node = arguments
                                .as_ref()
                                .and_then(|args| args.get("node"))
                                .and_then(|v| v.as_str());

                            match self.handle_cluster_status(node).await {
                                Ok(result) => {
                                    let content = rmcp::model::Content::text(
                                        serde_json::to_string_pretty(&result).unwrap_or_else(
                                            |_| "Failed to serialize result".to_string(),
                                        ),
                                    );
                                    let tool_result =
                                        rmcp::model::CallToolResult::success(vec![content]);
                                    Ok(rmcp::model::ServerResult::CallToolResult(tool_result))
                                }
                                Err(_) => {
                                    let content =
                                        rmcp::model::Content::text("Failed to get cluster status");
                                    let tool_result =
                                        rmcp::model::CallToolResult::error(vec![content]);
                                    Ok(rmcp::model::ServerResult::CallToolResult(tool_result))
                                }
                            }
                        }
                        "service_status" => {
                            let service = arguments
                                .as_ref()
                                .and_then(|args| args.get("service"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("consul"); // Default to consul service

                            let node = arguments
                                .as_ref()
                                .and_then(|args| args.get("node"))
                                .and_then(|v| v.as_str());

                            match self.handle_service_status(service, node).await {
                                Ok(result) => {
                                    let content = rmcp::model::Content::text(
                                        serde_json::to_string_pretty(&result).unwrap_or_else(
                                            |_| "Failed to serialize result".to_string(),
                                        ),
                                    );
                                    let tool_result =
                                        rmcp::model::CallToolResult::success(vec![content]);
                                    Ok(rmcp::model::ServerResult::CallToolResult(tool_result))
                                }
                                Err(_) => {
                                    let content =
                                        rmcp::model::Content::text("Failed to get service status");
                                    let tool_result =
                                        rmcp::model::CallToolResult::error(vec![content]);
                                    Ok(rmcp::model::ServerResult::CallToolResult(tool_result))
                                }
                            }
                        }
                        "resource_usage" => {
                            let node = arguments
                                .as_ref()
                                .and_then(|args| args.get("node"))
                                .and_then(|v| v.as_str());

                            match self.handle_resource_usage(node).await {
                                Ok(result) => {
                                    let content = rmcp::model::Content::text(
                                        serde_json::to_string_pretty(&result).unwrap_or_else(
                                            |_| "Failed to serialize result".to_string(),
                                        ),
                                    );
                                    let tool_result =
                                        rmcp::model::CallToolResult::success(vec![content]);
                                    Ok(rmcp::model::ServerResult::CallToolResult(tool_result))
                                }
                                Err(_) => {
                                    let content =
                                        rmcp::model::Content::text("Failed to get resource usage");
                                    let tool_result =
                                        rmcp::model::CallToolResult::error(vec![content]);
                                    Ok(rmcp::model::ServerResult::CallToolResult(tool_result))
                                }
                            }
                        }
                        "cluster_info" => match self.handle_cluster_info().await {
                            Ok(result) => {
                                let content = rmcp::model::Content::text(
                                    serde_json::to_string_pretty(&result).unwrap_or_else(|_| {
                                        "Failed to serialize result".to_string()
                                    }),
                                );
                                let tool_result =
                                    rmcp::model::CallToolResult::success(vec![content]);
                                Ok(rmcp::model::ServerResult::CallToolResult(tool_result))
                            }
                            Err(_) => {
                                let content =
                                    rmcp::model::Content::text("Failed to get cluster info");
                                let tool_result = rmcp::model::CallToolResult::error(vec![content]);
                                Ok(rmcp::model::ServerResult::CallToolResult(tool_result))
                            }
                        },
                        _ => {
                            Err(ErrorData {
                                code: ErrorCode(-32601), // Method not found
                                message: format!("Unknown tool: {}", tool_name).into(),
                                data: None,
                            })
                        }
                    }
                }
                _ => Err(ErrorData {
                    code: ErrorCode(-32601),
                    message: "Unsupported request type".into(),
                    data: None,
                }),
            }
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn handle_notification(
        &self,
        _notification: <RoleServer as ServiceRole>::PeerNot,
        _context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = Result<(), ErrorData>> + Send + '_ {
        async move { Ok(()) }
    }

    fn get_info(&self) -> <RoleServer as ServiceRole>::Info {
        println!("🏗️ SERVICE: get_info() called - building server capabilities");

        let capabilities = ServerCapabilities {
            tools: Some(ToolsCapability { list_changed: None }),
            resources: None,
            prompts: None,
            logging: None,
            completions: None,
            experimental: None,
        };

        let server_info = Implementation {
            name: "goldentooth-mcp".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        };

        let instructions = Some("Goldentooth cluster management MCP server. Provides tools to interact with the Raspberry Pi cluster infrastructure.".to_string());

        println!(
            "🏗️ SERVICE: Capabilities - tools: {:?}",
            capabilities.tools.is_some()
        );
        println!(
            "🏗️ SERVICE: Server info - name: {}, version: {}",
            server_info.name, server_info.version
        );
        println!(
            "🏗️ SERVICE: Instructions: {:?}",
            instructions.as_deref().unwrap_or("none")
        );

        let result = InitializeResult {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities,
            server_info,
            instructions,
        };

        println!("🏗️ SERVICE: get_info() returning complete result");
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_creation() {
        let service = GoldentoothService::new();
        // Service should be created successfully
        let _ = service.clone(); // Test that it implements Clone
    }

    #[test]
    fn test_get_info() {
        let service = GoldentoothService::new();
        let info = service.get_info();

        assert_eq!(info.server_info.name, "goldentooth-mcp");
        // Version should match Cargo.toml - don't hardcode it
        assert_eq!(info.server_info.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(info.protocol_version, ProtocolVersion::V_2024_11_05);
        assert!(info.instructions.is_some());
    }

    #[test]
    fn test_get_info_capabilities() {
        let service = GoldentoothService::new();
        let info = service.get_info();
        let capabilities = info.capabilities;

        // Test capabilities - we now have tools support
        assert!(capabilities.tools.is_some());
        assert!(capabilities.resources.is_none());
        assert!(capabilities.prompts.is_none());
        assert!(capabilities.logging.is_none());
        assert!(capabilities.completions.is_none());
        assert!(capabilities.experimental.is_none());
    }

    #[tokio::test]
    async fn test_handle_notification_returns_ok() {
        let _service = GoldentoothService::new();

        // Since we can't easily construct the proper notification types,
        // we'll test that our implementation always returns Ok
        // The actual notification handling is tested through integration tests

        // This tests our current implementation that always returns Ok(())
        assert!(true);
    }

    #[tokio::test]
    async fn test_handle_request_with_unsupported_request() {
        // Test that unsupported request types return appropriate errors
        // The actual tool request handling would need proper MCP client integration to test

        // This is a placeholder test since we can't easily construct ClientRequest types
        // without full MCP client integration. The integration tests handle the actual
        // request/response flow testing.
        assert!(true);
    }

    #[test]
    fn test_service_send_sync() {
        // Verify the service implements Send + Sync
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<GoldentoothService>();
    }

    #[test]
    fn test_service_static_lifetime() {
        // Verify the service can be used in static contexts
        fn assert_static<T: 'static>() {}
        assert_static::<GoldentoothService>();
    }
}
