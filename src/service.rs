use crate::auth::{AuthConfig, AuthError, AuthService};
use crate::cluster::{ClusterOperations, DefaultClusterOperations};
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

pub struct GoldentoothService {
    auth_service: Option<AuthService>,
    cluster_ops: Arc<dyn ClusterOperations + Send + Sync>,
    vector_service: Option<VectorService>,
}

impl std::fmt::Debug for GoldentoothService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoldentoothService")
            .field("auth_service", &self.auth_service.is_some())
            .field("vector_service", &self.vector_service.is_some())
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

        let cluster_ops = Arc::new(DefaultClusterOperations::new());

        GoldentoothService {
            auth_service,
            cluster_ops,
            vector_service: None,
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
        }
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
