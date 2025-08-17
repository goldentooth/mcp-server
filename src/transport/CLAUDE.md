# Transport Module

This module implements the transport layer for the MCP server, supporting both stdio and HTTP transports.

## Overview

The transport layer handles the physical communication between MCP clients and the server. It provides two transport modes that offer identical functionality but different connection methods.

## Module Structure

```
transport/
├── CLAUDE.md           # This documentation
├── mod.rs              # Transport module interface
├── stdio.rs            # Standard input/output transport
└── http.rs             # HTTP transport with SSE streaming
```

## Transport Types

### stdio Transport (`stdio.rs`)
- **Purpose**: Direct process communication via stdin/stdout
- **Protocol**: Newline-delimited JSON-RPC messages
- **Logging**: All logs go to stderr (never stdout/stdin)
- **Security**: Relies on process-level security
- **Usage**: Development, CLI tools, subprocess communication

### HTTP Transport (`http.rs`)
- **Purpose**: Network communication with web-based clients
- **Protocol**: HTTP POST with JSON-RPC payload, SSE streaming for responses
- **Endpoint**: Fixed `/mcp` endpoint
- **Security**: JWT authentication required, origin header validation
- **Logging**: All logs go to stderr, HTTP access logs included

## Key Features

### Dual Transport Requirement
Both transports MUST provide identical functionality:
- Same MCP tool availability
- Same error handling behavior
- Same response formats
- Same logging patterns

### HTTP Transport Specifics
- **Authentication**: JWT Bearer tokens validated against cluster PKI
- **Streaming**: Server-Sent Events (SSE) for real-time responses
- **Security**: DNS rebinding protection, origin validation
- **Configuration**: Environment-controlled binding (127.0.0.1 vs 0.0.0.0)
- **Connection Limits**: Maximum 100 concurrent connections
- **Payload Limits**: 1MB maximum request size

### Environment Configuration
- `MCP_LOCAL` - Bind HTTP to localhost only (127.0.0.1:port)
- `MCP_PORT` - HTTP port number (default: random)
- `MCP_AUTH_REQUIRED` - Enable/disable authentication (default: enabled)

## Protocol Compliance

Both transports implement the Model Context Protocol (MCP) specification:
- **Initialize**: Client handshake and capability negotiation
- **Tools**: List available tools and their schemas
- **Tool Calls**: Execute cluster management operations
- **Errors**: Standardized JSON-RPC error responses

## Security Model

### stdio Transport
- Process-level isolation
- No network exposure
- Direct file system access

### HTTP Transport
- Network-exposed (requires authentication)
- JWT token validation
- Origin header validation
- TLS termination at load balancer level
- Connection rate limiting

## Error Handling

All transports use consistent error patterns:
- JSON-RPC 2.0 error responses
- Structured error codes and messages
- Context preservation for debugging
- No sensitive information leakage

## Integration Points

### Authentication Module
HTTP transport integrates with `crate::auth::check_authentication()`

### Protocol Module
Both transports use `crate::protocol::process_json_request()`

### Tools Module
All cluster tools are accessible through both transports

## Development Guidelines

### Adding New Transport Features
1. Implement in both stdio and HTTP transports
2. Maintain identical functionality
3. Add comprehensive tests for both modes
4. Update documentation

### Testing Requirements
- Both transports must be equally testable
- Integration tests should cover both modes
- Authentication tests for HTTP transport
- Stream lifecycle tests for SSE

### Performance Considerations
- HTTP transport: <5s response times for cluster operations
- Connection pooling and reuse
- Graceful degradation when nodes unavailable
- Proper resource cleanup

## Logging Strategy

**Critical**: ALL logging goes to stderr, never stdout/stdin
- stdio transport: Logs to stderr only
- HTTP transport: Logs to stderr, structured JSON format
- No interleaving with MCP protocol messages
- Consistent log levels and formatting
