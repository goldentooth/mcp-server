# Goldentooth MCP Server Requirements

## Core Architecture

The Goldentooth MCP (Model Context Protocol) server is designed to provide AI assistant integration with cluster management capabilities. The server implements the MCP specification while adding robust operational features for production deployment.

## Transport Support

### Dual Transport Implementation
The server MUST support both MCP standard transports seamlessly:

1. **stdio Transport**
   - Launch as subprocess with JSON-RPC over stdin/stdout
   - Newline-delimited UTF-8 messages
   - Logging exclusively to stderr
   - Zero configuration required

2. **Streaming HTTP Transport**
   - HTTP POST/GET with optional Server-Sent Events
   - JSON-RPC over HTTP with SSE streaming support
   - Multiple concurrent client connections
   - Message resumability and redelivery

### Testing Requirements
- Both transports MUST be testable without friction or artificial limitation
- No transport-specific feature restrictions
- Identical functionality across both interfaces

## HTTP Transport Specifications

### Endpoint Configuration
- **MCP Endpoint**: `/mcp` (fixed, non-configurable)
- **Binding Behavior**:
  - `MCP_LOCAL` environment variable set (non-empty) → bind to `127.0.0.1`
  - `MCP_LOCAL` environment variable unset/empty → bind to `0.0.0.0`

### Security Requirements
- **Authentication**: Proper authentication MUST be implemented for ALL HTTP connections
- **Origin Validation**: Validate Origin header to prevent DNS rebinding attacks
- **Error Handling**: Always provide extremely detailed JSON-RPC error responses
- **Stream Management**: Always close SSE stream after JSON-RPC response

## Logging System

### Comprehensive Logging
- **Target**: stderr for all log output (never stdout/stdin)
- **System**: Feature-rich, powerful logging framework
- **Detail Level**: Extensive logging throughout the application
- **Structured**: JSON or structured format preferred for operational visibility

### Log Categories
- Transport layer operations (HTTP requests, stdio messages)
- Authentication events (success/failure/attempts)
- Cluster operation execution and results
- Error conditions with full context
- Performance metrics and timing

## Error Handling

### JSON-RPC Error Responses
- **Detail Level**: Extremely detailed error information
- **Context**: Include operation context, parameters, and failure reasons
- **Consistency**: Standardized error format across all operations
- **Security**: No sensitive information in error messages

### Stream Lifecycle
- **SSE Streams**: MUST be closed after each JSON-RPC response
- **Connection Management**: Proper cleanup of HTTP connections
- **Resource Management**: No resource leaks in long-running operations

## Implementation Constraints

### rmcp Package Integration
- Use `rmcp` crate as the foundational MCP implementation
- Requirements override `rmcp` defaults only where explicitly specified
- Maintain compatibility with `rmcp` API patterns
- Leverage `rmcp` JSON-RPC and transport abstractions

### Development Requirements
- **Language**: Rust 2024 edition
- **Async Runtime**: Tokio with full feature set
- **HTTP Framework**: Hyper-based implementation (already in Cargo.toml)
- **Serialization**: Serde for JSON handling

## Operational Features

### Cluster Integration
The server provides tools for:
- Cluster node health monitoring (ping, status checks)
- Service status verification across nodes
- Resource usage monitoring (CPU, memory, disk)
- Comprehensive cluster information aggregation
- Shell command execution on remote nodes
- Log aggregation from systemd journals and Loki

### Authentication Integration
- Support for existing Goldentooth cluster authentication
- Integration with cluster PKI/certificate infrastructure
- OAuth2 and JWT token support (dependencies already included)

## Testing Strategy

### Transport Testing
- Automated tests for both stdio and HTTP transports
- Integration tests with real MCP client implementations
- Performance testing under concurrent connections
- Error condition testing and recovery

### Cluster Integration Testing
- Mock cluster environment for development
- Integration tests with actual Goldentooth cluster nodes
- Authentication flow testing
- Error handling and timeout testing

## Non-Functional Requirements

### Performance
- Handle multiple concurrent HTTP connections
- Efficient resource usage on Raspberry Pi hardware
- Minimal latency for cluster status operations

### Reliability
- Graceful degradation when cluster nodes are unavailable
- Proper timeout handling for remote operations
- Connection pooling and reuse where appropriate

### Maintainability
- Clear separation between transport and business logic
- Modular architecture for cluster operation implementations
- Comprehensive error types and handling
- Documentation for all public interfaces

## Future Extensibility

### Plugin Architecture
- Modular tool implementation for easy extension
- Clear interface for adding new cluster operations
- Configuration-driven tool registration

### Monitoring Integration
- Metrics export for Prometheus integration
- Health check endpoints for load balancer integration
- Distributed tracing support for complex operations
