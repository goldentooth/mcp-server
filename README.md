# Goldentooth MCP Server

MCP (Model Context Protocol) server for Goldentooth cluster management.

## Overview

This server provides an MCP interface to interact with the Goldentooth Raspberry Pi cluster ("bramble"). It enables AI assistants to query cluster status, manage services, and perform administrative tasks.

The server automatically creates new releases with incremented versions on every commit to main.

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
The project includes comprehensive tests covering 100% of the public API:

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture
```

Test coverage includes:
- Service creation and cloning
- Server info structure (name, version, capabilities)
- Request handling (currently returns unimplemented)
- Notification handling (accepts all notifications)
- Service trait implementation (Send + Sync + 'static)
- Integration tests for service lifecycle

### Adding features
The server currently provides a minimal MCP implementation. To add tools and resources:

1. Implement tool handlers in the `handle_request` method
2. Add resource providers for cluster data
3. Update server capabilities in `get_info`
4. Add corresponding tests for new functionality

## License

This project is released under the Unlicense. See https://unlicense.org/ for details.
