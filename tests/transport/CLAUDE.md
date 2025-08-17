# Transport Tests

This directory contains tests for both stdio and HTTP transport implementations, ensuring parity and proper functionality.

## Test Files

### `http_transport.rs` & `http_transport_test.rs`
Core HTTP transport functionality testing:
- HTTP server startup and shutdown
- Request routing to `/mcp` endpoint
- POST request handling with JSON-RPC payloads
- Response formatting and headers
- Error handling and status codes

### `sse_stream_management.rs`
Server-Sent Events (SSE) streaming tests:
- SSE connection establishment
- Stream lifecycle management
- Event formatting and delivery
- Connection cleanup and resource management
- Concurrent stream handling

### `http_integration.rs`
End-to-end HTTP transport integration:
- Complete request/response cycles
- Authentication integration
- Tool execution through HTTP
- Error propagation through transport layer

### `transport_parity.rs`
Critical tests ensuring stdio and HTTP transports provide identical functionality:
- Same tool availability across both transports
- Identical response formats
- Consistent error handling
- Equivalent performance characteristics

## Transport Requirements

### Dual Transport Mandate
Both stdio and HTTP transports **MUST**:
- Support all available MCP tools
- Return identical response structures
- Handle errors consistently
- Provide same logging behavior
- Maintain identical security models (where applicable)

### HTTP Transport Specifics
- **Authentication**: JWT token validation for all requests
- **Endpoints**: Only `/mcp` endpoint supported
- **Methods**: POST for JSON-RPC, GET for SSE connections
- **Headers**: Proper CORS and security headers
- **Streaming**: SSE support for real-time responses

### stdio Transport Specifics
- **Protocol**: Newline-delimited JSON-RPC via stdin/stdout
- **Logging**: All logs to stderr (never stdout/stdin)
- **Security**: Process-level isolation
- **Streaming**: Sequential request/response model

## Test Categories

### Protocol Compliance
- JSON-RPC 2.0 specification adherence
- MCP protocol message formats
- Error response standardization
- Content-Type and encoding validation

### Connection Management
- Maximum connection limits (100 for HTTP)
- Connection timeout handling
- Resource cleanup on disconnect
- Graceful shutdown procedures

### Security Testing
- Authentication bypass prevention
- Origin header validation
- Payload size limits (1MB)
- Request rate limiting

### Performance Testing
- Response time requirements (<5s for cluster operations)
- Concurrent connection handling
- Memory usage under load
- Connection establishment latency

## Test Utilities

### Mock Servers
- HTTP test servers for integration testing
- Mock cluster nodes for tool testing
- Simulated network conditions
- Error injection capabilities

### Test Helpers
- JSON-RPC message builders
- SSE connection managers
- Authentication token generators
- Response validation utilities

## Critical Test Scenarios

### HTTP Transport
```rust
// Basic POST request handling
test_http_post_json_rpc()

// SSE connection lifecycle
test_sse_connection_management()

// Authentication integration
test_http_authentication_required()

// Error handling
test_http_error_responses()
```

### stdio Transport
```rust
// Message parsing and routing
test_stdio_message_handling()

// Error propagation
test_stdio_error_responses()

// Logging isolation
test_stdio_stderr_logging()
```

### Transport Parity
```rust
// Tool availability parity
test_all_tools_available_both_transports()

// Response format consistency
test_response_format_parity()

// Error handling consistency
test_error_handling_parity()
```

## Environment Configuration Testing

### HTTP Transport Configuration
- `MCP_LOCAL`: Localhost vs external binding
- `MCP_PORT`: Port configuration
- `MCP_AUTH_REQUIRED`: Authentication toggle

### Common Configuration
- `MCP_LOG_LEVEL`: Logging level control
- Environment variable validation
- Default value handling

## Integration with Other Modules

### Authentication Module
- HTTP transport authentication integration
- Token validation flow testing
- Authentication bypass testing

### Tools Module
- Tool execution through both transports
- Parameter validation across transports
- Error handling consistency

### Protocol Module
- Message routing and processing
- Response generation
- Error formatting

## Running Transport Tests

### All Transport Tests
```bash
cargo test transport::
```

### HTTP-Specific Tests
```bash
cargo test transport::http
```

### stdio-Specific Tests
```bash
cargo test transport::stdio
```

### Parity Tests (Critical)
```bash
cargo test transport::transport_parity
```

### Performance Tests
```bash
cargo test transport:: --release -- --ignored
```

## Continuous Integration Requirements

All transport tests must pass before deployment:
- Basic functionality tests
- Parity validation between transports
- Security validation for HTTP transport
- Performance benchmark compliance
- Integration test success

## Development Guidelines

### Adding New Transport Features
1. Implement in both stdio and HTTP transports
2. Add parity tests to verify identical behavior
3. Update transport documentation
4. Ensure security considerations addressed
5. Add performance validation if applicable

### Testing New Tools
1. Verify tool works in both transports
2. Add to parity test suite
3. Test error handling in both transports
4. Validate response format consistency
