# MCP Server Source Code Structure

This document provides an overview of the MCP server's source code organization and module responsibilities.

## Project Overview

The Goldentooth MCP Server is a Rust-based Model Context Protocol server that provides AI assistant integration with cluster management capabilities. It implements dual transport support (stdio and HTTP with SSE streaming) and offers comprehensive tools for managing a Raspberry Pi cluster infrastructure.

## Module Structure

```
src/
├── CLAUDE.md                    # This overview document
├── main.rs                      # Application entry point and CLI handling
├── lib.rs                       # Library interface and module declarations
│
├── auth/                        # JWT authentication system
│   ├── CLAUDE.md               # Authentication module documentation
│   ├── mod.rs                  # Main authentication interface
│   ├── jwt.rs                  # JWT token validation logic
│   └── bearer.rs               # Bearer token extraction
│
├── transport/                   # Communication layer
│   ├── CLAUDE.md               # Transport module documentation
│   ├── mod.rs                  # Transport interface
│   ├── stdio.rs                # Standard I/O transport
│   └── http.rs                 # HTTP transport with SSE
│
├── tools/                       # Cluster management tools
│   └── mod.rs                  # MCP tool implementations
│
├── cluster/                     # Cluster communication
│   └── mod.rs                  # SSH client and node management
│
├── types/                       # Type definitions and validation
│   ├── mod.rs                  # Type module interface
│   ├── mcp_message.rs          # MCP protocol message types
│   ├── tool_args.rs            # Type-safe tool arguments
│   ├── error_codes.rs          # Error code definitions
│   ├── type_safe_errors.rs     # Error handling types
│   ├── io_streams.rs           # I/O stream abstractions
│   ├── log_level.rs            # Logging level types
│   ├── protocol_state.rs       # Protocol state management
│   └── command_safety.rs       # Command validation
│
├── mcp/                         # MCP protocol integration
│   └── mod.rs                  # rmcp crate integration
│
├── protocol.rs                 # MCP message processing logic
├── logging/                     # Structured logging system
│   └── mod.rs                  # Logging configuration
│
└── error/                       # Error handling
    └── mod.rs                  # Error types and handling
```

## Module Responsibilities

### Core Architecture Modules

#### `main.rs` - Application Entry Point
- Command line argument parsing (`--version`, `--help`, `--http`)
- Environment variable handling (`MCP_LOG_LEVEL`, `MCP_LOCAL`)
- Transport mode selection (stdio vs HTTP)
- Application lifecycle management

#### `lib.rs` - Library Interface
- Public API definitions
- Module declarations and re-exports
- Integration points for external crates

#### `protocol.rs` - Message Processing
- MCP protocol message parsing and routing
- Request/response handling logic
- Tool execution coordination
- Error response generation

### Transport Layer

#### `transport/` - Communication Protocols
- **stdio**: Direct process communication via stdin/stdout
- **HTTP**: Network communication with authentication and SSE
- **Dual support**: Identical functionality across both transports

#### `auth/` - Security System
- JWT token validation using cluster PKI
- Bearer token extraction from HTTP headers
- Authentication bypass for development
- Integration with cluster certificate authority

### Business Logic

#### `tools/` - Cluster Management
- Type-safe MCP tool implementations
- Cluster status monitoring (`cluster_ping`, `cluster_status`)
- Service management (`service_status`)
- Resource monitoring (`resource_usage`)
- Remote command execution (`shell_command`)

#### `cluster/` - Infrastructure Integration
- SSH client for node communication
- Node management and health checking
- Integration with cluster services (Consul, Nomad, Vault)

### Supporting Systems

#### `types/` - Type Safety
- Strongly-typed tool arguments and validation
- MCP protocol message types
- Error handling and context preservation
- Command safety validation

#### `logging/` - Observability
- Structured JSON logging to stderr
- Log level configuration
- Integration with systemd journal

#### `error/` - Error Management
- Comprehensive error types and context
- JSON-RPC error response formatting
- Error code standardization

## Key Design Principles

### Type Safety
- Compile-time guarantees for tool arguments
- Strongly-typed protocol messages
- Input validation at multiple layers

### Security First
- Authentication required for HTTP transport
- Command validation and sanitization
- No sensitive information in error messages
- Origin header validation for web requests

### Transport Agnostic
- Identical functionality across stdio and HTTP
- Consistent error handling patterns
- Same tool availability regardless of transport

### Cluster Integration
- Leverages existing cluster PKI and services
- Integrates with Step-CA certificate management
- Uses cluster SSH configuration and keys

## Development Workflow

### Adding New Features
1. Define types in `types/` module
2. Implement core logic in appropriate module
3. Add transport support (both stdio and HTTP)
4. Include comprehensive tests
5. Update documentation

### Testing Strategy
- Unit tests for individual modules
- Integration tests for transport parity
- End-to-end tests against real cluster
- Security tests for authentication flows

### Documentation Requirements
- Each module includes CLAUDE.md documentation
- Function-level documentation with examples
- Architecture decision records for major changes
- API documentation for external integrations
