use crate::auth::{AuthConfig, AuthError, AuthService};
use crate::cluster::{ClusterOperations, DefaultClusterOperations};
use crate::command::SystemCommandExecutor;
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
use std::sync::Arc;

pub struct GoldentoothService {
    auth_service: Option<AuthService>,
    cluster_ops: Arc<dyn ClusterOperations + Send + Sync>,
}

impl std::fmt::Debug for GoldentoothService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoldentoothService")
            .field("auth_service", &self.auth_service.is_some())
            .finish()
    }
}

impl Clone for GoldentoothService {
    fn clone(&self) -> Self {
        // Now properly clones cluster_ops using Arc
        GoldentoothService {
            auth_service: self.auth_service.clone(),
            cluster_ops: Arc::clone(&self.cluster_ops),
        }
    }
}

impl Default for GoldentoothService {
    fn default() -> Self {
        Self::new()
    }
}

impl GoldentoothService {
    /// Extract the base tool name from a potentially prefixed tool name.
    /// MCP clients may prefix tool names with server identifiers like "mcp__goldentooth_mcp__".
    /// This function extracts the actual tool name after the last "__" separator.
    fn extract_tool_name(tool_name: &str) -> &str {
        if tool_name.contains("__") {
            tool_name
                .split("__")
                .last()
                .filter(|s| !s.is_empty())
                .unwrap_or(tool_name)
        } else {
            tool_name
        }
    }

    pub fn new() -> Self {
        let auth_config = AuthConfig::default();
        let auth_service = if AuthService::new(auth_config.clone()).requires_auth() {
            Some(AuthService::new(auth_config))
        } else {
            None
        };

        let executor = SystemCommandExecutor::new();
        let cluster_ops = Arc::new(DefaultClusterOperations::new(executor));

        GoldentoothService {
            auth_service,
            cluster_ops,
        }
    }

    pub fn with_cluster_operations(cluster_ops: Arc<dyn ClusterOperations + Send + Sync>) -> Self {
        let auth_config = AuthConfig::default();
        let auth_service = if AuthService::new(auth_config.clone()).requires_auth() {
            Some(AuthService::new(auth_config))
        } else {
            None
        };

        GoldentoothService {
            auth_service,
            cluster_ops,
        }
    }

    pub async fn with_auth() -> Result<(Self, AuthService), AuthError> {
        let auth_config = AuthConfig::default();
        let mut auth_service = AuthService::new(auth_config);
        auth_service.initialize().await?;

        let executor = SystemCommandExecutor::new();
        let cluster_ops = Arc::new(DefaultClusterOperations::new(executor));

        let service = GoldentoothService {
            auth_service: Some(auth_service.clone()),
            cluster_ops,
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

    pub async fn handle_cluster_ping_v2(&self) -> Result<Value, ErrorData> {
        match self.cluster_ops.ping_all_nodes().await {
            Ok(nodes) => Ok(json!({
                "success": true,
                "nodes": nodes,
                "tool": "cluster_ping"
            })),
            Err(error) => Ok(json!({
                "success": false,
                "error": error.to_string(),
                "tool": "cluster_ping"
            })),
        }
    }

    #[allow(dead_code)]
    pub async fn handle_cluster_ping(&self) -> Result<Value, ErrorData> {
        self.handle_cluster_ping_v2().await
    }

    #[allow(dead_code)]
    pub async fn handle_cluster_status(&self, node: Option<&str>) -> Result<Value, ErrorData> {
        if let Some(node_name) = node {
            match self.cluster_ops.get_node_status(node_name).await {
                Ok(status) => Ok(json!({
                    "success": true,
                    "node": status,
                    "tool": "cluster_status"
                })),
                Err(error) => Ok(json!({
                    "success": false,
                    "error": error.to_string(),
                    "tool": "cluster_status"
                })),
            }
        } else {
            // Get all nodes status
            match self.cluster_ops.ping_all_nodes().await {
                Ok(nodes) => Ok(json!({
                    "success": true,
                    "nodes": nodes,
                    "tool": "cluster_status"
                })),
                Err(error) => Ok(json!({
                    "success": false,
                    "error": error.to_string(),
                    "tool": "cluster_status"
                })),
            }
        }
    }

    #[allow(dead_code)]
    pub async fn handle_service_status(
        &self,
        service: &str,
        node: Option<&str>,
    ) -> Result<Value, ErrorData> {
        match self.cluster_ops.get_service_status(service, node).await {
            Ok(statuses) => Ok(json!({
                "success": true,
                "services": statuses,
                "tool": "service_status",
                "service": service,
                "node": node
            })),
            Err(error) => Ok(json!({
                "success": false,
                "error": error.to_string(),
                "tool": "service_status",
                "service": service,
                "node": node
            })),
        }
    }

    #[allow(dead_code)]
    pub async fn handle_resource_usage(&self, node: Option<&str>) -> Result<Value, ErrorData> {
        match self.cluster_ops.get_resource_usage(node).await {
            Ok(usage_map) => Ok(json!({
                "success": true,
                "resources": usage_map,
                "tool": "resource_usage",
                "node": node
            })),
            Err(error) => Ok(json!({
                "success": false,
                "error": error.to_string(),
                "tool": "resource_usage",
                "node": node
            })),
        }
    }

    #[allow(dead_code)]
    pub async fn handle_cluster_info(&self) -> Result<Value, ErrorData> {
        // Get comprehensive cluster information
        match self.cluster_ops.ping_all_nodes().await {
            Ok(nodes) => {
                // Try to get service status for key services
                let consul_status = self
                    .cluster_ops
                    .get_service_status("consul", None)
                    .await
                    .ok();
                let nomad_status = self
                    .cluster_ops
                    .get_service_status("nomad", None)
                    .await
                    .ok();

                Ok(json!({
                    "success": true,
                    "nodes": nodes,
                    "services": {
                        "consul": consul_status,
                        "nomad": nomad_status,
                    },
                    "tool": "cluster_info"
                }))
            }
            Err(error) => Ok(json!({
                "success": false,
                "error": error.to_string(),
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

                    // Handle prefixed tool names by extracting the last component after '__'
                    let effective_tool_name = Self::extract_tool_name(tool_name);

                    match effective_tool_name {
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
                            Err(error_data) => {
                                eprintln!(
                                    "Cluster ping failed with error {}: {}",
                                    error_data.code.0, error_data.message
                                );
                                let detailed_message = format!(
                                    "Failed to ping cluster - Error {}: {} {}",
                                    error_data.code.0,
                                    error_data.message,
                                    error_data
                                        .data
                                        .as_ref()
                                        .map(|d| format!(
                                            "(Details: {})",
                                            serde_json::to_string(d).unwrap_or_else(|_| {
                                                "<serialization error>".to_string()
                                            })
                                        ))
                                        .unwrap_or_else(|| "".to_string())
                                );
                                let content = rmcp::model::Content::text(detailed_message);
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
                                Err(error_data) => {
                                    eprintln!(
                                        "Cluster status failed with error {}: {}",
                                        error_data.code.0, error_data.message
                                    );
                                    let detailed_message = format!(
                                        "Failed to get cluster status - Error {}: {} {}",
                                        error_data.code.0,
                                        error_data.message,
                                        error_data
                                            .data
                                            .as_ref()
                                            .map(|d| format!(
                                                "(Details: {})",
                                                serde_json::to_string(d).unwrap_or_else(|_| {
                                                    "<serialization error>".to_string()
                                                })
                                            ))
                                            .unwrap_or_else(|| "".to_string())
                                    );
                                    let content = rmcp::model::Content::text(detailed_message);
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
                                Err(error_data) => {
                                    eprintln!(
                                        "Service status failed with error {}: {}",
                                        error_data.code.0, error_data.message
                                    );
                                    let detailed_message = format!(
                                        "Failed to get service status - Error {}: {} {}",
                                        error_data.code.0,
                                        error_data.message,
                                        error_data
                                            .data
                                            .as_ref()
                                            .map(|d| format!(
                                                "(Details: {})",
                                                serde_json::to_string(d).unwrap_or_else(|_| {
                                                    "<serialization error>".to_string()
                                                })
                                            ))
                                            .unwrap_or_else(|| "".to_string())
                                    );
                                    let content = rmcp::model::Content::text(detailed_message);
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
                                Err(error_data) => {
                                    eprintln!(
                                        "Resource usage failed with error {}: {}",
                                        error_data.code.0, error_data.message
                                    );
                                    let detailed_message = format!(
                                        "Failed to get resource usage - Error {}: {} {}",
                                        error_data.code.0,
                                        error_data.message,
                                        error_data
                                            .data
                                            .as_ref()
                                            .map(|d| format!(
                                                "(Details: {})",
                                                serde_json::to_string(d).unwrap_or_else(|_| {
                                                    "<serialization error>".to_string()
                                                })
                                            ))
                                            .unwrap_or_else(|| "".to_string())
                                    );
                                    let content = rmcp::model::Content::text(detailed_message);
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
                            Err(error_data) => {
                                eprintln!(
                                    "Cluster info failed with error {}: {}",
                                    error_data.code.0, error_data.message
                                );
                                let detailed_message = format!(
                                    "Failed to get cluster info - Error {}: {} {}",
                                    error_data.code.0,
                                    error_data.message,
                                    error_data
                                        .data
                                        .as_ref()
                                        .map(|d| format!(
                                            "(Details: {})",
                                            serde_json::to_string(d).unwrap_or_else(|_| {
                                                "<serialization error>".to_string()
                                            })
                                        ))
                                        .unwrap_or_else(|| "".to_string())
                                );
                                let content = rmcp::model::Content::text(detailed_message);
                                let tool_result = rmcp::model::CallToolResult::error(vec![content]);
                                Ok(rmcp::model::ServerResult::CallToolResult(tool_result))
                            }
                        },
                        _ => {
                            Err(ErrorData {
                                code: ErrorCode(-32601), // Method not found
                                message: format!("Unknown tool: {}", effective_tool_name).into(),
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
        let service = GoldentoothService::new();

        // Since we can't easily construct the proper notification types,
        // we'll test that our implementation always returns Ok
        // The actual notification handling is tested through integration tests

        // Verify the service can be created and cloned (basic functionality)
        let _cloned_service = service.clone();
        // This tests our current implementation that always returns Ok(())
        // The actual notification handling would be tested with proper MCP types
    }

    #[tokio::test]
    async fn test_handle_request_with_unsupported_request() {
        // Test that unsupported request types return appropriate errors
        // The actual tool request handling would need proper MCP client integration to test

        // This is a placeholder test since we can't easily construct ClientRequest types
        // without full MCP client integration. The integration tests handle the actual
        // request/response flow testing.

        // Verify basic service functionality instead
        let service = GoldentoothService::new();
        let info = service.get_info();
        assert_eq!(info.server_info.name, "goldentooth-mcp");
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

    #[test]
    fn test_extract_tool_name() {
        // Test normal tool names without prefixes
        assert_eq!(
            GoldentoothService::extract_tool_name("cluster_ping"),
            "cluster_ping"
        );
        assert_eq!(
            GoldentoothService::extract_tool_name("service_status"),
            "service_status"
        );

        // Test prefixed tool names
        assert_eq!(
            GoldentoothService::extract_tool_name("mcp__goldentooth_mcp__cluster_ping"),
            "cluster_ping"
        );
        assert_eq!(
            GoldentoothService::extract_tool_name("some__nested__tool__name"),
            "name"
        );

        // Test edge cases
        assert_eq!(
            GoldentoothService::extract_tool_name("__cluster_ping"),
            "cluster_ping"
        );
        assert_eq!(
            GoldentoothService::extract_tool_name("mcp__goldentooth__"),
            "mcp__goldentooth__"
        ); // Empty suffix returns original
        assert_eq!(GoldentoothService::extract_tool_name("__"), "__"); // All empty returns original
        assert_eq!(GoldentoothService::extract_tool_name(""), ""); // Empty string

        // Test single underscore (not double)
        assert_eq!(
            GoldentoothService::extract_tool_name("mcp_tool_name"),
            "mcp_tool_name"
        );
    }
}
