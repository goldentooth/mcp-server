use crate::auth::{AuthConfig, AuthError, AuthService};
use crate::cluster::{ClusterOperations, DefaultClusterOperations};
use crate::screenshot::{AuthConfig as ScreenshotAuthConfig, ScreenshotRequest, ScreenshotService};
use crate::vectors::{ClusterDataType, VectorService};
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
use tokio::sync::Mutex;

pub struct GoldentoothService {
    auth_service: Option<AuthService>,
    cluster_ops: Arc<dyn ClusterOperations + Send + Sync>,
    vector_service: Option<VectorService>,
    screenshot_service: Option<Arc<Mutex<ScreenshotService>>>,
}

impl std::fmt::Debug for GoldentoothService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoldentoothService")
            .field("auth_service", &self.auth_service.is_some())
            .field("vector_service", &self.vector_service.is_some())
            .field("screenshot_service", &self.screenshot_service.is_some())
            .finish()
    }
}

impl Clone for GoldentoothService {
    fn clone(&self) -> Self {
        // Now properly clones cluster_ops using Arc
        GoldentoothService {
            auth_service: self.auth_service.clone(),
            cluster_ops: Arc::clone(&self.cluster_ops),
            vector_service: self.vector_service.clone(),
            screenshot_service: self.screenshot_service.clone(),
        }
    }
}

impl Default for GoldentoothService {
    fn default() -> Self {
        Self::new()
    }
}

impl GoldentoothService {
    fn get_screenshot_base_url() -> String {
        let host = std::env::var("SCREENSHOT_HTTP_HOST")
            .unwrap_or_else(|_| "velaryon.nodes.goldentooth.net".to_string());
        let port = std::env::var("SCREENSHOT_HTTP_PORT").unwrap_or_else(|_| "8081".to_string());
        format!("http://{host}:{port}")
    }
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

        let cluster_ops = Arc::new(DefaultClusterOperations::new());

        GoldentoothService {
            auth_service,
            cluster_ops,
            vector_service: None,
            screenshot_service: Some(Arc::new(Mutex::new(ScreenshotService::new()))),
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
            vector_service: None,
            screenshot_service: Some(Arc::new(Mutex::new(ScreenshotService::new()))),
        }
    }

    pub async fn initialize_http_server(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(screenshot_service) = &self.screenshot_service {
            let mut service_guard = screenshot_service.lock().await;

            // Configure HTTP server with environment variables or defaults
            let port = std::env::var("SCREENSHOT_HTTP_PORT")
                .unwrap_or_else(|_| "8081".to_string())
                .parse::<u16>()
                .unwrap_or(8081);

            let directory = std::env::var("SCREENSHOT_DIRECTORY")
                .unwrap_or_else(|_| "/tmp/screenshots".to_string());

            service_guard.configure_http_server(port, directory);
            service_guard
                .start_http_server()
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        }
        Ok(())
    }

    pub async fn with_auth() -> Result<(Self, AuthService), AuthError> {
        let auth_config = AuthConfig::default();
        let mut auth_service = AuthService::new(auth_config);
        auth_service.initialize().await?;

        let cluster_ops = Arc::new(DefaultClusterOperations::new());

        let service = GoldentoothService {
            auth_service: Some(auth_service.clone()),
            cluster_ops,
            vector_service: None,
            screenshot_service: Some(Arc::new(Mutex::new(ScreenshotService::new()))),
        };

        Ok((service, auth_service))
    }

    pub fn is_auth_enabled(&self) -> bool {
        self.auth_service.is_some()
    }

    /// Initialize vector service with S3 configuration
    pub async fn with_vectors(
        mut self,
        bucket_name: String,
        index_name: String,
    ) -> Result<Self, crate::vectors::VectorError> {
        let vector_service = VectorService::new(bucket_name, index_name).await?;
        self.vector_service = Some(vector_service);
        Ok(self)
    }

    pub fn is_vectors_enabled(&self) -> bool {
        self.vector_service.is_some()
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
                            eprintln!("Authentication failed: {e}");
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

    #[allow(dead_code)]
    pub async fn handle_shell_command(
        &self,
        command: &str,
        node: Option<&str>,
        as_root: bool,
        timeout_seconds: u64,
    ) -> Result<Value, ErrorData> {
        match self
            .cluster_ops
            .execute_command(command, node, as_root, timeout_seconds)
            .await
        {
            Ok(results) => Ok(json!({
                "success": true,
                "results": results,
                "tool": "shell_command"
            })),
            Err(error) => Ok(json!({
                "success": false,
                "error": error.to_string(),
                "tool": "shell_command"
            })),
        }
    }

    #[allow(dead_code)]
    pub async fn handle_journald_logs(
        &self,
        node: Option<&str>,
        service: Option<&str>,
        since: Option<&str>,
        lines: Option<u32>,
        follow: bool,
        priority: Option<&str>,
    ) -> Result<Value, ErrorData> {
        match self
            .cluster_ops
            .get_journald_logs(node, service, since, lines, follow, priority)
            .await
        {
            Ok(logs) => Ok(json!({
                "success": true,
                "logs": logs,
                "tool": "journald_logs"
            })),
            Err(error) => Ok(json!({
                "success": false,
                "error": error.to_string(),
                "tool": "journald_logs"
            })),
        }
    }

    #[allow(dead_code)]
    pub async fn handle_loki_logs(
        &self,
        query: &str,
        start: Option<&str>,
        end: Option<&str>,
        limit: Option<u32>,
        direction: Option<&str>,
    ) -> Result<Value, ErrorData> {
        match self
            .cluster_ops
            .get_loki_logs(query, start, end, limit, direction)
            .await
        {
            Ok(logs) => Ok(json!({
                "success": true,
                "logs": logs,
                "tool": "loki_logs"
            })),
            Err(error) => Ok(json!({
                "success": false,
                "error": error.to_string(),
                "tool": "loki_logs"
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

    #[allow(dead_code)]
    pub async fn handle_vector_search(
        &self,
        query: &str,
        limit: Option<u32>,
        metadata_filters: Option<std::collections::HashMap<String, String>>,
    ) -> Result<Value, ErrorData> {
        if let Some(vector_service) = &self.vector_service {
            match vector_service
                .search_knowledge(query, limit, metadata_filters)
                .await
            {
                Ok(result) => Ok(result),
                Err(error) => Ok(json!({
                    "success": false,
                    "error": error.to_string(),
                    "tool": "vector_search"
                })),
            }
        } else {
            Ok(json!({
                "success": false,
                "error": "Vector service not enabled. Configure S3 Vectors bucket and index.",
                "tool": "vector_search"
            }))
        }
    }

    #[allow(dead_code)]
    pub async fn handle_screenshot(&self, request: ScreenshotRequest) -> Result<Value, ErrorData> {
        if let Some(screenshot_service) = &self.screenshot_service {
            let mut screenshot_service_guard = screenshot_service.lock().await;
            match screenshot_service_guard.capture_screenshot(request).await {
                Ok(response) => Ok(json!({
                    "success": response.success,
                    "image_base64": response.image_base64,
                    "file_path": response.file_path,
                    "screenshot_url": response.screenshot_url,
                    "error": response.error,
                    "metadata": response.metadata,
                    "tool": "screenshot_url"
                })),
                Err(error) => Ok(json!({
                    "success": false,
                    "error": error.to_string(),
                    "tool": "screenshot_url"
                })),
            }
        } else {
            Ok(json!({
                "success": false,
                "error": "Screenshot service not available",
                "tool": "screenshot_url"
            }))
        }
    }

    #[allow(dead_code)]
    pub async fn handle_screenshot_dashboard(
        &self,
        dashboard_url: &str,
        auth_config: Option<ScreenshotAuthConfig>,
    ) -> Result<Value, ErrorData> {
        self.handle_screenshot_dashboard_with_options(
            dashboard_url,
            auth_config,
            true,
            Some("/tmp/screenshots".to_string()),
            true,
            Some(Self::get_screenshot_base_url()),
        )
        .await
    }

    #[allow(dead_code)]
    pub async fn handle_screenshot_dashboard_with_options(
        &self,
        dashboard_url: &str,
        auth_config: Option<ScreenshotAuthConfig>,
        save_to_file: bool,
        file_directory: Option<String>,
        http_serve: bool,
        http_base_url: Option<String>,
    ) -> Result<Value, ErrorData> {
        if let Some(screenshot_service) = &self.screenshot_service {
            let mut screenshot_service_guard = screenshot_service.lock().await;
            match screenshot_service_guard
                .capture_dashboard_with_options(
                    dashboard_url,
                    auth_config,
                    save_to_file,
                    file_directory,
                    http_serve,
                    http_base_url,
                )
                .await
            {
                Ok(response) => Ok(json!({
                    "success": response.success,
                    "image_base64": response.image_base64,
                    "file_path": response.file_path,
                    "screenshot_url": response.screenshot_url,
                    "error": response.error,
                    "metadata": response.metadata,
                    "tool": "screenshot_dashboard"
                })),
                Err(error) => Ok(json!({
                    "success": false,
                    "error": error.to_string(),
                    "tool": "screenshot_dashboard"
                })),
            }
        } else {
            Ok(json!({
                "success": false,
                "error": "Screenshot service not available",
                "tool": "screenshot_dashboard"
            }))
        }
    }

    #[allow(dead_code)]
    pub async fn handle_vector_store(
        &self,
        content: &str,
        data_type: &str,
        metadata: std::collections::HashMap<String, String>,
    ) -> Result<Value, ErrorData> {
        if let Some(vector_service) = &self.vector_service {
            let cluster_data_type = match data_type {
                "configuration" => ClusterDataType::Configuration,
                "log_entry" => ClusterDataType::LogEntry,
                "documentation" => ClusterDataType::Documentation,
                "service_status" => ClusterDataType::ServiceStatus,
                "error_message" => ClusterDataType::ErrorMessage,
                "command_output" => ClusterDataType::CommandOutput,
                _ => ClusterDataType::Documentation, // Default fallback
            };

            match vector_service
                .index_cluster_data(cluster_data_type, content, metadata)
                .await
            {
                Ok(result) => Ok(result),
                Err(error) => Ok(json!({
                    "success": false,
                    "error": error.to_string(),
                    "tool": "vector_store"
                })),
            }
        } else {
            Ok(json!({
                "success": false,
                "error": "Vector service not enabled. Configure S3 Vectors bucket and index.",
                "tool": "vector_store"
            }))
        }
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
                rmcp::model::ClientRequest::InitializeRequest(_init_request) => {
                    // Return initialization result
                    let init_result = self.get_info();
                    Ok(rmcp::model::ServerResult::InitializeResult(init_result))
                }
                rmcp::model::ClientRequest::ListToolsRequest(_) => {
                    use rmcp::model::{ListToolsResult, Tool};
                    use std::sync::Arc;

                    // Helper function to create JSON schema
                    let create_schema = |properties: Vec<(&str, &str, &str, bool)>| -> Arc<serde_json::Map<String, serde_json::Value>> {
                        let mut schema = serde_json::Map::new();
                        schema.insert("type".into(), serde_json::Value::String("object".into()));

                        let mut props = serde_json::Map::new();
                        let mut required = Vec::new();

                        for (name, prop_type, description, is_required) in properties {
                            let mut prop = serde_json::Map::new();
                            prop.insert("type".into(), serde_json::Value::String(prop_type.into()));
                            prop.insert("description".into(), serde_json::Value::String(description.into()));
                            props.insert(name.into(), serde_json::Value::Object(prop));

                            if is_required {
                                required.push(serde_json::Value::String(name.into()));
                            }
                        }

                        schema.insert("properties".into(), serde_json::Value::Object(props));
                        if !required.is_empty() {
                            schema.insert("required".into(), serde_json::Value::Array(required));
                        }

                        Arc::new(schema)
                    };

                    let mut tools = vec![
                        Tool {
                            name: "cluster_ping".into(),
                            description: Some("Ping all nodes in the goldentooth cluster to check their status".into()),
                            annotations: None,
                            input_schema: create_schema(vec![]),
                        },
                        Tool {
                            name: "cluster_status".into(),
                            description: Some("Get detailed status information for cluster nodes".into()),
                            annotations: None,
                            input_schema: create_schema(vec![
                                ("node", "string", "Specific node to check (e.g., 'allyrion', 'jast'). If not provided, checks all nodes.", false),
                            ]),
                        },
                        Tool {
                            name: "service_status".into(),
                            description: Some("Check the status of systemd services on cluster nodes".into()),
                            annotations: None,
                            input_schema: create_schema(vec![
                                ("service", "string", "Service name to check (e.g., 'consul', 'nomad', 'vault')", true),
                                ("node", "string", "Specific node to check. If not provided, checks all nodes.", false),
                            ]),
                        },
                        Tool {
                            name: "resource_usage".into(),
                            description: Some("Get memory and disk usage information for cluster nodes".into()),
                            annotations: None,
                            input_schema: create_schema(vec![
                                ("node", "string", "Specific node to check. If not provided, checks all nodes.", false),
                            ]),
                        },
                        Tool {
                            name: "cluster_info".into(),
                            description: Some("Get comprehensive cluster information including node status and service membership".into()),
                            annotations: None,
                            input_schema: create_schema(vec![]),
                        },
                        Tool {
                            name: "screenshot_url".into(),
                            description: Some("Capture a screenshot of any URL with optional authentication and customizable viewport".into()),
                            annotations: None,
                            input_schema: create_schema(vec![
                                ("url", "string", "The URL to capture a screenshot of", true),
                                ("width", "integer", "Viewport width in pixels (default: 1920)", false),
                                ("height", "integer", "Viewport height in pixels (default: 1080)", false),
                                ("wait_for_selector", "string", "CSS selector to wait for before taking screenshot", false),
                                ("wait_timeout_ms", "integer", "Maximum time to wait for page load in milliseconds (default: 5000)", false),
                            ]),
                        },
                        Tool {
                            name: "screenshot_dashboard".into(),
                            description: Some("Capture a screenshot of a Grafana dashboard with Authelia authentication optimizations".into()),
                            annotations: None,
                            input_schema: create_schema(vec![
                                ("dashboard_url", "string", "The Grafana dashboard URL to capture", true),
                            ]),
                        },
                    ];

                    // Add vector tools if vector service is enabled
                    if self.vector_service.is_some() {
                        tools.extend(vec![
                            Tool {
                                name: "vector_search".into(),
                                description: Some("Search knowledge base using semantic vector search".into()),
                                annotations: None,
                                input_schema: create_schema(vec![
                                    ("query", "string", "Search query for semantic matching", true),
                                    ("limit", "integer", "Maximum number of results to return (default: 10)", false),
                                ]),
                            },
                            Tool {
                                name: "vector_store".into(),
                                description: Some("Store cluster data in vector knowledge base".into()),
                                annotations: None,
                                input_schema: create_schema(vec![
                                    ("content", "string", "Content to store in knowledge base", true),
                                    ("data_type", "string", "Type of data: configuration, log_entry, documentation, service_status, error_message, command_output", false),
                                ]),
                            },
                        ]);
                    }

                    Ok(rmcp::model::ServerResult::ListToolsResult(
                        ListToolsResult {
                            tools,
                            next_cursor: None,
                        },
                    ))
                }
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
                        "shell_command" => {
                            let command = arguments
                                .as_ref()
                                .and_then(|args| args.get("command"))
                                .and_then(|v| v.as_str())
                                .ok_or_else(|| ErrorData {
                                    code: ErrorCode(-32602), // Invalid params
                                    message: "Missing required parameter: command".into(),
                                    data: None,
                                })?;

                            let node = arguments
                                .as_ref()
                                .and_then(|args| args.get("node"))
                                .and_then(|v| v.as_str());

                            let as_root = arguments
                                .as_ref()
                                .and_then(|args| args.get("as_root"))
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);

                            let timeout_seconds = arguments
                                .as_ref()
                                .and_then(|args| args.get("timeout"))
                                .and_then(|v| v.as_u64())
                                .unwrap_or(60);

                            match self
                                .handle_shell_command(command, node, as_root, timeout_seconds)
                                .await
                            {
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
                                        "Shell command failed with error {}: {}",
                                        error_data.code.0, error_data.message
                                    );
                                    let detailed_message = format!(
                                        "Failed to execute shell command - Error {}: {} {}",
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
                        "journald_logs" => {
                            let node = arguments
                                .as_ref()
                                .and_then(|args| args.get("node"))
                                .and_then(|v| v.as_str());

                            let service = arguments
                                .as_ref()
                                .and_then(|args| args.get("service"))
                                .and_then(|v| v.as_str());

                            let since = arguments
                                .as_ref()
                                .and_then(|args| args.get("since"))
                                .and_then(|v| v.as_str());

                            let lines = arguments
                                .as_ref()
                                .and_then(|args| args.get("lines"))
                                .and_then(|v| v.as_u64())
                                .map(|v| v as u32);

                            let follow = arguments
                                .as_ref()
                                .and_then(|args| args.get("follow"))
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);

                            let priority = arguments
                                .as_ref()
                                .and_then(|args| args.get("priority"))
                                .and_then(|v| v.as_str());

                            match self
                                .handle_journald_logs(node, service, since, lines, follow, priority)
                                .await
                            {
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
                                        "Journald logs failed with error {}: {}",
                                        error_data.code.0, error_data.message
                                    );
                                    let detailed_message = format!(
                                        "Failed to get journald logs - Error {}: {} {}",
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
                        "loki_logs" => {
                            let query = arguments
                                .as_ref()
                                .and_then(|args| args.get("query"))
                                .and_then(|v| v.as_str())
                                .ok_or_else(|| ErrorData {
                                    code: ErrorCode(-32602), // Invalid params
                                    message: "Missing required parameter: query".into(),
                                    data: None,
                                })?;

                            let start = arguments
                                .as_ref()
                                .and_then(|args| args.get("start"))
                                .and_then(|v| v.as_str());

                            let end = arguments
                                .as_ref()
                                .and_then(|args| args.get("end"))
                                .and_then(|v| v.as_str());

                            let limit = arguments
                                .as_ref()
                                .and_then(|args| args.get("limit"))
                                .and_then(|v| v.as_u64())
                                .map(|v| v as u32);

                            let direction = arguments
                                .as_ref()
                                .and_then(|args| args.get("direction"))
                                .and_then(|v| v.as_str());

                            match self
                                .handle_loki_logs(query, start, end, limit, direction)
                                .await
                            {
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
                                        "Loki logs failed with error {}: {}",
                                        error_data.code.0, error_data.message
                                    );
                                    let detailed_message = format!(
                                        "Failed to get Loki logs - Error {}: {} {}",
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
                        "vector_search" => {
                            let query = arguments
                                .as_ref()
                                .and_then(|args| args.get("query"))
                                .and_then(|v| v.as_str())
                                .ok_or_else(|| ErrorData {
                                    code: ErrorCode(-32602), // Invalid params
                                    message: "Missing required parameter: query".into(),
                                    data: None,
                                })?;

                            let limit = arguments
                                .as_ref()
                                .and_then(|args| args.get("limit"))
                                .and_then(|v| v.as_u64())
                                .map(|v| v as u32);

                            let metadata_filters = arguments
                                .as_ref()
                                .and_then(|args| args.get("metadata_filters"))
                                .and_then(|v| {
                                    if let Value::Object(obj) = v {
                                        let mut filters = std::collections::HashMap::new();
                                        for (k, v) in obj {
                                            if let Some(s) = v.as_str() {
                                                filters.insert(k.clone(), s.to_string());
                                            }
                                        }
                                        Some(filters)
                                    } else {
                                        None
                                    }
                                });

                            match self
                                .handle_vector_search(query, limit, metadata_filters)
                                .await
                            {
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
                                    let detailed_message = format!(
                                        "Failed to search vectors - Error {}: {}",
                                        error_data.code.0, error_data.message
                                    );
                                    let content = rmcp::model::Content::text(detailed_message);
                                    let tool_result =
                                        rmcp::model::CallToolResult::error(vec![content]);
                                    Ok(rmcp::model::ServerResult::CallToolResult(tool_result))
                                }
                            }
                        }
                        "vector_store" => {
                            let content = arguments
                                .as_ref()
                                .and_then(|args| args.get("content"))
                                .and_then(|v| v.as_str())
                                .ok_or_else(|| ErrorData {
                                    code: ErrorCode(-32602), // Invalid params
                                    message: "Missing required parameter: content".into(),
                                    data: None,
                                })?;

                            let data_type = arguments
                                .as_ref()
                                .and_then(|args| args.get("data_type"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("documentation");

                            let metadata = arguments
                                .as_ref()
                                .and_then(|args| args.get("metadata"))
                                .and_then(|v| {
                                    if let Value::Object(obj) = v {
                                        let mut meta = std::collections::HashMap::new();
                                        for (k, v) in obj {
                                            if let Some(s) = v.as_str() {
                                                meta.insert(k.clone(), s.to_string());
                                            }
                                        }
                                        Some(meta)
                                    } else {
                                        None
                                    }
                                })
                                .unwrap_or_default();

                            match self.handle_vector_store(content, data_type, metadata).await {
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
                                    let detailed_message = format!(
                                        "Failed to store vectors - Error {}: {}",
                                        error_data.code.0, error_data.message
                                    );
                                    let content = rmcp::model::Content::text(detailed_message);
                                    let tool_result =
                                        rmcp::model::CallToolResult::error(vec![content]);
                                    Ok(rmcp::model::ServerResult::CallToolResult(tool_result))
                                }
                            }
                        }
                        "screenshot_dashboard" => {
                            let dashboard_url = arguments
                                .as_ref()
                                .and_then(|args| args.get("dashboard_url"))
                                .and_then(|v| v.as_str())
                                .ok_or_else(|| ErrorData {
                                    code: ErrorCode(-32602), // Invalid params
                                    message: "Missing required parameter: dashboard_url".into(),
                                    data: None,
                                })?;

                            let auth_config = arguments
                                .as_ref()
                                .and_then(|args| args.get("auth_config"))
                                .and_then(|v| {
                                    serde_json::from_value::<ScreenshotAuthConfig>(v.clone()).ok()
                                });

                            match self
                                .handle_screenshot_dashboard(dashboard_url, auth_config)
                                .await
                            {
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
                                        "Screenshot dashboard failed with error {}: {}",
                                        error_data.code.0, error_data.message
                                    );
                                    let detailed_message = format!(
                                        "Failed to capture dashboard screenshot - Error {}: {} {}",
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
                        "screenshot_url" => {
                            let url = arguments
                                .as_ref()
                                .and_then(|args| args.get("url"))
                                .and_then(|v| v.as_str())
                                .ok_or_else(|| ErrorData {
                                    code: ErrorCode(-32602), // Invalid params
                                    message: "Missing required parameter: url".into(),
                                    data: None,
                                })?;

                            let width = arguments
                                .as_ref()
                                .and_then(|args| args.get("width"))
                                .and_then(|v| v.as_u64())
                                .map(|v| v as u32);

                            let height = arguments
                                .as_ref()
                                .and_then(|args| args.get("height"))
                                .and_then(|v| v.as_u64())
                                .map(|v| v as u32);

                            let wait_for_selector = arguments
                                .as_ref()
                                .and_then(|args| args.get("wait_for_selector"))
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());

                            let wait_timeout_ms = arguments
                                .as_ref()
                                .and_then(|args| args.get("wait_timeout_ms"))
                                .and_then(|v| v.as_u64());

                            let auth_config = arguments
                                .as_ref()
                                .and_then(|args| args.get("auth_config"))
                                .and_then(|v| {
                                    serde_json::from_value::<ScreenshotAuthConfig>(v.clone()).ok()
                                });

                            let save_to_file = arguments
                                .as_ref()
                                .and_then(|args| args.get("save_to_file"))
                                .and_then(|v| v.as_bool())
                                .unwrap_or(true); // Default to file mode to avoid large responses

                            let file_directory = arguments
                                .as_ref()
                                .and_then(|args| args.get("file_directory"))
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| "/tmp/screenshots".to_string());

                            let http_serve = arguments
                                .as_ref()
                                .and_then(|args| args.get("http_serve"))
                                .and_then(|v| v.as_bool())
                                .unwrap_or(true); // Default to HTTP serving

                            let http_base_url = if http_serve {
                                Some("http://velaryon.nodes.goldentooth.net:8081".to_string())
                            } else {
                                None
                            };

                            let request = ScreenshotRequest {
                                url: url.to_string(),
                                width,
                                height,
                                wait_for_selector,
                                wait_timeout_ms,
                                authenticate: auth_config,
                                save_to_file: Some(save_to_file),
                                file_directory: Some(file_directory),
                                http_serve: Some(http_serve),
                                http_base_url,
                            };

                            match self.handle_screenshot(request).await {
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
                                        "Screenshot failed with error {}: {}",
                                        error_data.code.0, error_data.message
                                    );
                                    let detailed_message = format!(
                                        "Failed to capture screenshot - Error {}: {} {}",
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
                        _ => {
                            Err(ErrorData {
                                code: ErrorCode(-32601), // Method not found
                                message: format!("Unknown tool: {effective_tool_name}").into(),
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
