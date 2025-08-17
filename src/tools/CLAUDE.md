# Tools Module

This module implements the MCP tool system for cluster management operations. All tools provide type-safe arguments and comprehensive error handling.

## Overview

The tools module provides a type-safe interface for cluster operations using the MCP (Model Context Protocol) standard. Each tool implements the `TypeSafeMcpTool` trait and provides compile-time guarantees for argument validation.

## Tool Structure

```
src/tools/
├── CLAUDE.md          # This documentation
└── mod.rs             # All tool implementations
```

## Available Tools

### Stage 3 Tools (Core Operations)

#### `cluster_ping`
**Purpose**: Test connectivity to all cluster nodes using ICMP and TCP checks
**Arguments**: None
**Output**: Node-by-node ping results with timing and port availability

#### `cluster_status`
**Purpose**: Get detailed health information from node_exporter metrics
**Arguments**:
- `node` (optional): Specific node to check
**Output**: System metrics including CPU, memory, disk, network

#### `service_status`
**Purpose**: Check systemd service status across cluster nodes
**Arguments**:
- `service` (required): Service name to check
- `node` (optional): Specific node to check
**Output**: Service state, memory usage, uptime, restart history

#### `resource_usage`
**Purpose**: Get resource utilization summary for monitoring
**Arguments**:
- `node` (optional): Specific node to check
**Output**: Memory, disk, CPU usage with percentages

#### `shell_command`
**Purpose**: Execute shell commands on cluster nodes via SSH
**Arguments**:
- `command` (required): Shell command (security validated)
- `node` (optional): Target node (defaults to allyrion)
- `as_root` (optional): Execute as root user
- `timeout` (optional): Command timeout in seconds
**Output**: Exit code, stdout, stderr, execution metadata

### Stage 4 Tools (Advanced Operations)

#### `cluster_info`
**Purpose**: Comprehensive cluster state aggregation with health analysis
**Arguments**: None
**Output**: Complete cluster overview including:
- All node statuses and resource usage
- Critical service health across the cluster
- Summary statistics and health indicators
- Cluster-wide resource totals and averages

#### `journald_logs`
**Purpose**: Query systemd journal logs with advanced filtering
**Arguments**:
- `node` (optional): Target node (defaults to allyrion)
- `service` (optional): Filter by systemd service/unit
- `priority` (optional): Log priority level (0=emergency, 7=debug)
- `since` (optional): Time constraint (e.g., "1 hour ago")
- `lines` (optional): Maximum lines to return (default: 100, max: 1000)
- `follow` (optional): Real-time following (not supported, always false)
**Output**: Structured log entries with metadata

#### `loki_logs`
**Purpose**: Query Loki logging system using LogQL syntax
**Arguments**:
- `query` (required): LogQL query string (e.g., `{job="consul"}`)
- `start` (optional): Start time for query range
- `end` (optional): End time for query range
- `limit` (optional): Maximum log entries (default: 100, max: 5000)
- `direction` (optional): Query direction (forward/backward)
**Output**: Structured log entries with stream labels and timestamps

## Type Safety Features

### Compile-Time Validation
- Tool arguments are validated at compile time using Rust's type system
- Invalid combinations of parameters are caught during development
- Tool names are checked against registered tool implementations

### Runtime Safety
- Command safety validation prevents dangerous operations
- Node names are validated against known cluster nodes
- Service names are validated for proper formatting
- LogQL queries are validated for correct syntax

### Error Handling
All tools follow consistent error patterns:
- Structured JSON-RPC error responses
- Context preservation for debugging
- No sensitive information in error messages
- Graceful degradation when nodes are unavailable

## Security Model

### Command Execution Safety
- Shell commands are validated against dangerous patterns
- Root execution requires explicit permission
- Command timeouts prevent hanging operations
- All commands are logged for audit trails

### Network Security
- SSH key-based authentication to cluster nodes
- No plaintext credentials in tool operations
- Origin validation for HTTP transport
- Rate limiting and connection management

### Access Controls
- Tools respect cluster PKI and certificate authority
- Authentication required for HTTP transport
- Process-level isolation for stdio transport
- Comprehensive logging for security auditing

## Performance Characteristics

### Response Time Targets
- Local operations: <1 second
- Single node operations: <5 seconds
- Cluster-wide operations: <15 seconds
- Log queries: <10 seconds (depending on range)

### Resource Usage
- Memory efficient with streaming for large responses
- Connection pooling for multiple node operations
- Automatic cleanup of temporary resources
- Graceful handling of network timeouts

### Scalability
- Concurrent execution across multiple nodes
- Configurable parallelism limits
- Resource usage monitoring
- Connection limit enforcement

## Development Guidelines

### Adding New Tools
1. Define argument types in `src/types/tool_args.rs`
2. Implement `TypeSafeMcpTool` trait in `src/tools/mod.rs`
3. Add tool to execution and parsing functions
4. Create comprehensive tests
5. Update documentation

### Tool Implementation Pattern
```rust
pub struct NewTool;

#[async_trait]
impl TypeSafeMcpTool<NewToolArgs> for NewTool {
    fn description(&self) -> &str {
        "Tool description"
    }

    fn input_schema(&self) -> Value {
        // JSON schema for arguments
    }

    async fn execute(&self, args: NewToolArgs) -> ToolResult<Value> {
        // Implementation
    }
}
```

### Error Handling Best Practices
- Use structured error types with context
- Include operation metadata in responses
- Handle network failures gracefully
- Provide actionable error messages

## Integration with Cluster Infrastructure

### SSH Integration
- Uses cluster SSH configuration and keys
- Leverages existing node connectivity
- Respects cluster security policies
- Integrates with cluster certificate authority

### Service Discovery
- Consul integration for service health
- Automatic node discovery from cluster config
- Service mesh awareness
- Health check integration

### Observability Integration
- Prometheus metrics export
- Loki log aggregation
- Grafana dashboard compatibility
- Vector log pipeline integration

### HashiCorp Stack Integration
- Consul service registry queries
- Nomad workload information
- Vault secrets management (where applicable)
- Cluster state coordination

## Testing Strategy

### Unit Tests
- Individual tool functionality
- Argument validation
- Error handling paths
- Edge case coverage

### Integration Tests
- End-to-end tool execution
- Real cluster node testing
- Service interaction validation
- Performance benchmarking

### Security Tests
- Command injection prevention
- Authentication bypass testing
- Authorization validation
- Audit trail verification

## Monitoring and Observability

### Metrics Collection
- Tool execution latency
- Success/failure rates
- Resource usage per tool
- Concurrent operation counts

### Logging
- All tool executions logged
- Structured JSON format
- Security-relevant events
- Performance metrics

### Health Checks
- Tool availability monitoring
- Dependency health validation
- Performance threshold alerting
- Capacity planning data

## Future Enhancements

### Stage 5 Tools (Planned)
- `screenshot_url`: Web page capture
- `screenshot_dashboard`: Authenticated dashboard capture
- AWS service integrations
- Enhanced automation capabilities

### Potential Improvements
- Caching for frequently accessed data
- Streaming responses for large datasets
- WebSocket support for real-time updates
- Plugin system for custom tools
