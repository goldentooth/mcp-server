# Goldentooth MCP Server Architecture

## Overview

The Goldentooth MCP server implements a dual-transport Model Context Protocol server with extensive cluster management capabilities. The architecture emphasizes modularity, testability, and operational robustness.

## Core Architecture Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    Client Applications                      │
└─────────────────┬───────────────────┬───────────────────────┘
                  │                   │
          ┌───────▼────────┐ ┌────────▼────────┐
          │  stdio Client  │ │  HTTP Client    │
          │                │ │  (SSE Stream)   │
          └───────┬────────┘ └────────┬────────┘
                  │                   │
┌─────────────────▼───────────────────▼─────────────────────────┐
│                Transport Layer                                │
│  ┌─────────────────┐    ┌──────────────────────────────────┐  │
│  │ stdio Transport │    │      HTTP Transport              │  │
│  │  - stdin/stdout │    │  - /mcp endpoint                 │  │
│  │  - newline msgs │    │  - SSE streaming                 │  │
│  │                 │    │  - authentication                │  │
│  └─────────────────┘    └──────────────────────────────────┘  │
└─────────────────┬───────────────────┬─────────────────────────┘
                  │                   │
┌─────────────────▼───────────────────▼─────────────────────────┐
│                   MCP Protocol Layer                          │
│                (rmcp crate integration)                       │
│  - JSON-RPC message handling                                  │
│  - MCP method dispatch                                        │
│  - Error standardization                                      │
└─────────────────────────┬─────────────────────────────────────┘
                          │
┌─────────────────────────▼────────────────────────────────────┐
│                    Tool Layer                                │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐  │
│  │ Cluster Ping │ │ Node Status  │ │ Resource Monitoring  │  │
│  │ Service Mgmt │ │ Log Queries  │ │ Screenshot Capture   │  │
│  └──────────────┘ └──────────────┘ └──────────────────────┘  │
└─────────────────────────┬────────────────────────────────────┘
                          │
┌─────────────────────────▼────────────────────────────────────┐
│                Infrastructure Layer                          │
│  ┌────────────────────┐ ┌─────────────────┐ ┌─────────────┐  │
│  │   Goldentooth      │ │   AWS Services  │ │  Kubernetes │  │
│  │     Cluster        │ │      APIs       │ │     APIs    │  │
│  │  - SSH execution   │ │  - S3, Bedrock  │ │  - kubectl  │  │
│  │  - systemd logs    │ │  - Route53      │ │  - resources│  │
│  └────────────────────┘ └─────────────────┘ └─────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

## Transport Implementation

### stdio Transport
- **Process Model**: Server runs as subprocess, communicates via stdin/stdout
- **Message Format**: Newline-delimited JSON-RPC messages
- **Logging**: All logs to stderr (never stdout)
- **Lifecycle**: Launched and managed by client process

### HTTP Transport
- **Server Model**: Standalone HTTP server with SSE streaming
- **Endpoint**: Fixed `/mcp` endpoint for all MCP operations
- **Binding**: Environment-controlled (`MCP_LOCAL` variable)
- **Authentication**: Required for all connections
- **Streaming**: SSE for real-time message delivery

## Module Structure

### Core Modules

```rust
src/
├── main.rs                 // Entry point and transport selection
├── lib.rs                  // Public API and re-exports
├── transport/
│   ├── mod.rs             // Transport trait definitions
│   ├── stdio.rs           // stdio transport implementation
│   └── http.rs            // HTTP/SSE transport implementation
├── mcp/
│   ├── mod.rs             // MCP protocol integration
│   ├── server.rs          // MCP server implementation
│   └── tools.rs           // Tool registry and dispatch
├── tools/
│   ├── mod.rs             // Tool trait and registry
│   ├── cluster.rs         // Cluster management tools
│   ├── monitoring.rs      // Resource monitoring tools
│   ├── logs.rs            // Log aggregation tools
│   └── screenshot.rs      // Screenshot capture tools
├── cluster/
│   ├── mod.rs             // Cluster abstraction layer
│   ├── ssh.rs             // SSH client implementation
│   ├── nodes.rs           // Node management
│   └── services.rs        // Service status checking
├── auth/
│   ├── mod.rs             // Authentication framework
│   ├── oauth.rs           // OAuth2 implementation
│   └── jwt.rs             // JWT token validation
├── logging/
│   ├── mod.rs             // Logging configuration
│   └── structured.rs      // Structured logging formats
└── error/
    ├── mod.rs             // Error type definitions
    └── json_rpc.rs        // JSON-RPC error formatting
```

### Key Traits

```rust
// Transport abstraction
pub trait Transport {
    async fn start(&self) -> Result<(), TransportError>;
    async fn send_message(&self, message: JsonRpcMessage) -> Result<(), TransportError>;
    async fn receive_message(&self) -> Result<JsonRpcMessage, TransportError>;
}

// Tool implementation interface
pub trait McpTool {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn input_schema(&self) -> serde_json::Value;
    async fn execute(&self, params: serde_json::Value) -> Result<serde_json::Value, McpError>;
}

// Cluster operations abstraction
pub trait ClusterClient {
    async fn ping_node(&self, node: &str) -> Result<PingResult, ClusterError>;
    async fn execute_command(&self, node: &str, command: &str) -> Result<CommandResult, ClusterError>;
    async fn get_service_status(&self, node: &str, service: &str) -> Result<ServiceStatus, ClusterError>;
}
```

## Configuration Management

### Environment Variables
- `MCP_LOCAL`: Controls HTTP binding (127.0.0.1 vs 0.0.0.0)
- `GOLDENTOOTH_CLUSTER_CONFIG`: Cluster configuration file path
- `MCP_AUTH_METHOD`: Authentication method selection
- `MCP_LOG_LEVEL`: Logging verbosity control
- `MCP_BIND_PORT`: HTTP server port (default: 8080)

### Configuration Files
- `cluster.toml`: Cluster node definitions and SSH configuration
- `auth.toml`: Authentication provider configuration
- `tools.toml`: Tool enablement and configuration

## Error Handling Strategy

### Error Type Hierarchy
```rust
#[derive(thiserror::Error, Debug)]
pub enum McpError {
    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("Cluster operation failed: {0}")]
    Cluster(#[from] ClusterError),

    #[error("Authentication failed: {0}")]
    Auth(#[from] AuthError),

    #[error("Tool execution failed: {tool}: {message}")]
    Tool { tool: String, message: String },

    #[error("JSON-RPC protocol error: {0}")]
    JsonRpc(#[from] JsonRpcError),
}
```

### JSON-RPC Error Mapping
- Detailed error context in `data` field
- Standardized error codes for common failures
- No sensitive information leakage
- Operation traceability for debugging

## Security Model

### HTTP Authentication
- OAuth2 authorization code flow
- JWT token validation with cluster CA
- Origin header validation (DNS rebinding protection)
- Rate limiting per client connection

### Cluster Access
- SSH key-based authentication to nodes
- Certificate-based service authentication
- Vault integration for secrets management
- Principle of least privilege for operations

## Testing Strategy

### Unit Tests
- Transport layer isolation testing
- Tool execution mocking
- Error condition simulation
- Authentication flow testing

### Integration Tests
- End-to-end MCP client testing
- Real cluster integration testing
- Multi-transport consistency validation
- Performance and concurrency testing

### Development Tools
- Mock cluster for local development
- Transport switching without code changes
- Comprehensive logging for debugging
- Health check endpoints for monitoring

## Deployment Considerations

### Systemd Integration
- Service files for HTTP transport mode
- Automatic restart and failure handling
- Log integration with systemd journal
- Resource limits and security sandboxing

### Container Support
- Docker image with both transport modes
- Kubernetes deployment manifests
- Health check endpoint configuration
- Secret injection for cluster credentials

### Monitoring Integration
- Prometheus metrics export
- Grafana dashboard integration
- Distributed tracing support
- Performance monitoring and alerting
