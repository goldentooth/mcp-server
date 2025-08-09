# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

The Goldentooth MCP Server is a Rust-based Model Context Protocol (MCP) server that provides AI assistant integration with cluster management capabilities. It implements dual transport support (stdio and HTTP with SSE streaming) and offers comprehensive tools for managing a Raspberry Pi cluster infrastructure.

## Architecture

### Core Design
- **Dual Transport**: Both stdio (subprocess) and HTTP/SSE (streaming) transports
- **Tool-Based**: Modular tool system for cluster operations
- **Async Runtime**: Built on Tokio with rmcp crate foundation
- **Security-First**: OAuth2/JWT authentication, origin validation, comprehensive logging

### Module Structure
```
src/
├── transport/     # stdio and HTTP transport implementations
├── mcp/          # MCP protocol integration with rmcp
├── tools/        # Cluster management tool implementations
├── cluster/      # SSH client and node management
├── auth/         # OAuth2/JWT authentication
├── logging/      # Structured logging to stderr
└── error/        # Comprehensive error handling
```

## Development Commands

### Building
```bash
# Debug build
cargo build

# Release build
cargo build --release

# Cross-compilation for Pi cluster
cargo build --release --target aarch64-unknown-linux-gnu
```

### Testing
```bash
# Unit tests
cargo test

# Integration tests with specific features
cargo test --features integration

# Test with verbose output
cargo test -- --nocapture
```

### Code Quality
```bash
# Linting
cargo clippy

# Formatting
cargo fmt

# Full check pipeline
cargo clippy && cargo fmt && cargo test
```

### Running
```bash
# stdio mode (development)
cargo run

# HTTP mode with local binding
MCP_LOCAL=1 cargo run

# HTTP mode with external binding
cargo run
```

## Key Implementation Details

### Transport Layer
- **stdio**: Newline-delimited JSON-RPC over stdin/stdout, logs to stderr
- **HTTP**: Fixed `/mcp` endpoint with SSE streaming, environment-controlled binding (`MCP_LOCAL`)
- Both transports must provide identical functionality and error handling

### Tool System
All cluster management tools implement the `McpTool` trait:
- `cluster_ping`: ICMP/TCP connectivity testing
- `cluster_status`: Node health via node_exporter metrics
- `service_status`: systemd service monitoring
- `resource_usage`: CPU, memory, disk utilization
- `cluster_info`: Comprehensive cluster state aggregation
- `shell_command`: Remote command execution via SSH
- `journald_logs`: systemd journal log aggregation
- `loki_logs`: LogQL querying of Loki logs
- `screenshot_url`: Headless Chrome webpage capture
- `screenshot_dashboard`: Authenticated dashboard capture

### Error Handling
- **Comprehensive**: All operations return detailed JSON-RPC error responses
- **Structured**: Error types hierarchy with context preservation
- **Secure**: No sensitive information in error messages
- **Traceable**: Full operation context for debugging

### Authentication
- **HTTP Transport**: Required OAuth2/JWT with cluster PKI integration
- **stdio Transport**: Relies on process-level security
- **Cluster Access**: SSH key-based authentication to nodes
- **Security**: Origin header validation, DNS rebinding protection

## Integration with Goldentooth Cluster

### Cluster Configuration
- Integrates with existing `goldentooth` CLI infrastructure
- Uses cluster SSH configuration and PKI certificates
- Leverages Consul service discovery and Vault secrets management
- Accesses Prometheus metrics and Loki logs

### Node Management
- **Target Nodes**: 12 Raspberry Pi nodes (allyrion, bettley, etc.) + velaryon GPU node
- **Services**: Kubernetes, HashiCorp stack (Consul/Nomad/Vault), observability tools
- **Authentication**: Step-CA certificates, SSH keys, JWT tokens

### Operational Context
- **Deployment**: Systemd service with automatic restart
- **Monitoring**: Prometheus metrics export, health check endpoints
- **Logging**: JSON-structured logs to stderr for systemd journal integration

## Development Workflow

### Project State
This is a complete architectural rewrite with comprehensive planning documentation:
- `REQUIREMENTS.md`: Detailed functional and non-functional requirements
- `ARCHITECTURE.md`: System design and module structure
- `IMPLEMENTATION_PLAN.md`: 5-stage development plan with success criteria

### Quality Standards
- **Testing**: Both transport modes must be equally testable
- **Security**: Authentication required for all HTTP connections
- **Performance**: <5s response times for cluster status operations (network-bound)
- **Reliability**: Graceful degradation when nodes unavailable

### Implementation Guidelines
- Use `rmcp` crate patterns and abstractions
- Implement comprehensive logging throughout (stderr only)
- Maintain transport-agnostic tool implementations
- Follow existing Goldentooth cluster conventions and PKI
- Never bypass pre-commit checks or alter configurations to pass checks

## Dependencies and Tools

### Core Dependencies
- `rmcp`: MCP protocol implementation foundation
- `tokio`: Async runtime with full feature set
- `hyper`: HTTP server implementation
- `oauth2`, `jsonwebtoken`: Authentication
- `thiserror`: Error handling
- `headless_chrome`: Screenshot capture

### Development Tools
- Cross-compilation support for ARM64 (Pi cluster deployment)
- Integration with existing Goldentooth `goldentooth` CLI
- Systemd service files for production deployment
- Health check endpoints for monitoring integration

## Important Notes

- **Logging**: ALL logs must go to stderr (never stdout/stdin)
- **Transports**: Both stdio and HTTP must work identically
- **Security**: Authentication is mandatory for HTTP transport
- **Streams**: SSE streams must be closed after each JSON-RPC response
- **Environment**: `MCP_LOCAL` controls HTTP binding behavior (127.0.0.1 vs 0.0.0.0)
