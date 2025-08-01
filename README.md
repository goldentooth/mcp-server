# Goldentooth MCP Server

MCP (Model Context Protocol) server for Goldentooth cluster management.

## Overview

This server provides an MCP interface to interact with the Goldentooth Raspberry Pi cluster ("bramble"). It enables AI assistants to query cluster status, manage services, and perform administrative tasks through a set of dedicated tools.

The server automatically creates new releases with incremented versions on every commit to main.

## Available MCP Tools

The server provides the following tools for cluster management:

- **`cluster_ping`** - Ping all cluster nodes to check connectivity using ICMP (with TCP fallback)
- **`cluster_status`** - Get detailed status information including uptime and load averages via node_exporter metrics
- **`service_status`** - Check systemd service status across nodes via node_exporter systemd metrics
- **`resource_usage`** - Get memory and disk usage information via node_exporter resource metrics
- **`cluster_info`** - Get comprehensive cluster information including node status and service membership

All tools support both prefixed (`mcp__goldentooth_mcp__cluster_ping`) and unprefixed (`cluster_ping`) naming conventions for compatibility with different MCP clients.

### Tool Parameters

- **`cluster_ping`** - No parameters required
- **`cluster_status`** - Optional `node` parameter to check a specific node (e.g., `"allyrion"`)
- **`service_status`** - Required `service` parameter (e.g., `"consul"`, `"nomad"`, `"vault"`), optional `node` parameter
- **`resource_usage`** - Optional `node` parameter to check a specific node
- **`cluster_info`** - No parameters required

## Building

### Prerequisites
- Rust 1.70 or later
- Cargo

### Build for current architecture
```bash
cargo build --release
```

### Cross-compile for Raspberry Pi (ARM64)
```bash
# Install cross-compilation toolchain
rustup target add aarch64-unknown-linux-gnu

# Build for ARM64
cargo build --release --target aarch64-unknown-linux-gnu
```

## Installation

### Local development
```bash
cargo install --path .
```

### System-wide deployment
```bash
# Build release binary
cargo build --release

# Copy to system location
sudo cp target/release/goldentooth-mcp /usr/local/bin/

# Install systemd service
sudo cp goldentooth-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable goldentooth-mcp
sudo systemctl start goldentooth-mcp
```

## Usage

### Running locally

#### Without authentication (development)
```bash
# Development mode
cargo run

# HTTP mode for web integration
cargo run -- --http

# Or if installed
goldentooth-mcp
```

#### With Authelia authentication
```bash
# Set authentication credentials
export OAUTH_CLIENT_SECRET=your-actual-client-secret
export AUTHELIA_BASE_URL=https://auth.goldentooth.net:9091

# Run with authentication enabled
cargo run -- --http
```

### Testing with MCP client
```bash
# The server communicates via stdin/stdout by default
echo '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"0.1.0","capabilities":{}},"id":1}' | goldentooth-mcp

# Or test HTTP mode on localhost:8080
curl -X POST http://localhost:8080/mcp/request \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"0.1.0","capabilities":{}},"id":1}'
```

## Authentication

The MCP server supports optional authentication via Authelia OIDC. See [AUTHENTICATION.md](AUTHENTICATION.md) for detailed configuration and usage instructions.

### Quick Start with Authentication

1. **Configure environment variables:**
   ```bash
   export OAUTH_CLIENT_SECRET=your-actual-secret
   export OAUTH_CLIENT_ID=goldentooth-mcp  # optional, has default
   export AUTHELIA_BASE_URL=https://auth.goldentooth.net:9091  # optional, has default
   ```

2. **Test authentication setup:**
   ```bash
   cargo run --example test_auth
   ```

3. **Run server with authentication:**
   ```bash
   cargo run -- --http
   ```

When authentication is enabled, all MCP requests must include a valid JWT token in the Authorization header.

## Development

### Setting up pre-commit hooks
This project uses pre-commit to ensure code quality:

```bash
# Install pre-commit
pip install pre-commit

# Install the git hooks
pre-commit install

# Run manually on all files
pre-commit run --all-files
```

The pre-commit configuration includes:
- `rustfmt` - Automatic code formatting
- `clippy` - Rust linting with warnings as errors
- `cargo check` - Ensure code compiles
- `cargo test` - Run all tests
- General file hygiene (trailing whitespace, EOF, etc.)

### Project structure
- `src/main.rs` - Main server entry point
- `src/service.rs` - MCP service implementation
- `src/lib.rs` - Library exports
- `tests/` - Integration tests
- `goldentooth-mcp.service` - Systemd service file

### Testing
The project includes comprehensive tests covering all functionality:

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_extract_tool_name
```

Test coverage includes:
- Service creation and cloning
- Server info structure (name, version, capabilities)
- MCP tool request handling for all 5 tools
- Tool name extraction (prefixed/unprefixed handling)
- Notification handling (accepts all notifications)
- Service trait implementation (Send + Sync + 'static)
- Authentication flow and JWT validation
- HTTP server endpoints and error handling
- Integration tests for service lifecycle
- Security tests (certificate validation, secret disclosure prevention)

### Adding features
The server provides a full MCP implementation with cluster management tools. To add new tools and resources:

1. Add new tool handlers in the `handle_request` method's match statement
2. Implement the tool logic in dedicated handler methods (following the `handle_*` pattern)
3. Add resource providers for cluster data if needed
4. Update server capabilities in `get_info` if adding new capability types
5. Add comprehensive unit tests for new functionality
6. Update this README with documentation for new tools

## Troubleshooting

### Common Issues

#### "Method not found" (-32601) errors
- **Cause**: MCP client is sending prefixed tool names that don't match server expectations
- **Solution**: This should be automatically handled as of v0.0.23+. Ensure you're using the latest version.
- **Verification**: The server supports both `cluster_ping` and `mcp__goldentooth_mcp__cluster_ping` formats

#### Authentication failures
- **Cause**: Missing or invalid OAuth configuration
- **Solution**: Verify `OAUTH_CLIENT_SECRET` and `AUTHELIA_BASE_URL` environment variables
- **Test**: Run `cargo run --example test_auth` to verify authentication setup

#### Connection refused errors
- **Cause**: Server not running or wrong port
- **Solution**: Check if server is running with `systemctl status goldentooth-mcp` or start manually
- **Default ports**: 8080 for HTTP mode, stdin/stdout for MCP mode

#### Permission denied accessing cluster nodes
- **Cause**: SSH keys not properly configured or missing cluster access
- **Solution**: Ensure the server has appropriate SSH access to cluster nodes
- **Test**: Manually SSH to cluster nodes to verify connectivity

### Deployment with Ansible

The MCP server can be deployed across the cluster using the Goldentooth Ansible role:

```bash
# Deploy to all cluster nodes
goldentooth setup_mcp_server

# Or manually with Ansible
cd ../ansible
ansible-playbook playbooks/setup_mcp_server.yaml
```

## License

This project is released under the Unlicense. See https://unlicense.org/ for details.
