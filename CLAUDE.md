# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust-based MCP (Model Context Protocol) server for the Goldentooth cluster management system. The server provides an interface for AI assistants to interact with a Raspberry Pi cluster ("bramble") through the MCP protocol, enabling cluster status queries, service management, and administrative tasks.

## Essential Commands

### Development Workflow
```bash
# Build and run
cargo run                              # Run development server
cargo build --release                 # Production build

# Testing
cargo test                            # Run all tests
cargo test -- --nocapture           # Run tests with output
cargo test test_service_creation     # Run specific test

# Code Quality
cargo clippy -- -D warnings         # Lint with warnings as errors
rustfmt --edition=2024 src/*.rs     # Format code
pre-commit run --all-files          # Run all pre-commit hooks

# Cross-compilation for Raspberry Pi deployment
cargo build --release --target aarch64-unknown-linux-gnu
```

### Pre-commit Setup
```bash
pre-commit install                   # Install git hooks (required for development)
```

## Architecture Overview

### Core Components

**`GoldentoothService`** - The central MCP service implementation that:
- Implements the `Service<RoleServer>` trait from the `rmcp` crate
- Handles MCP protocol requests and notifications
- Currently returns `unimplemented!()` for requests (ready for extension)
- Accepts all notifications without processing

**MCP Protocol Integration** - Uses the `rmcp` crate (v0.2.0) with:
- Server-side MCP implementation via `ServiceExt` trait
- stdin/stdout transport for communication
- JSON-RPC based protocol handling

### Project Structure

```
src/
├── main.rs     # Entry point, sets up transport and starts server
├── service.rs  # Core GoldentoothService implementation and tests
└── lib.rs      # Module exports for testing

tests/
└── integration_test.rs  # Integration tests for service lifecycle
```

### Key Design Patterns

**Service Architecture** - The MCP service is implemented as a stateless, cloneable struct that:
- Implements `Clone + Send + Sync + 'static` for concurrent usage
- Uses async trait methods with explicit Future return types (required by rmcp trait)
- Separates protocol handling from business logic

**Testing Strategy** - Comprehensive test coverage includes:
- Unit tests for all public API methods
- Integration tests for service lifecycle
- Tests for trait bounds and static lifetime requirements
- Mock transport testing using `tokio::io::duplex`

## Development Notes

### MCP Protocol Implementation

The server implements the MCP server role using the `rmcp` crate. Key methods:
- `handle_request()` - Currently unimplemented, ready for tool/resource handlers
- `handle_notification()` - Accepts all notifications (returns `Ok(())`)
- `get_info()` - Returns server metadata and capabilities

### Code Quality Enforcement

Pre-commit hooks enforce:
- Rust formatting (edition 2024)
- Clippy linting with warnings as errors
- Compilation verification
- Test execution
- File hygiene

### Extension Points

To add MCP tools and resources:
1. Implement handlers in `handle_request()` method in `src/service.rs`
2. Update server capabilities in `get_info()` method
3. Add corresponding unit and integration tests
4. Update version in `Cargo.toml` and service info

### CI/CD Pipeline

GitHub Actions provides automated versioning and releases:

**Version Bump Workflow** (runs on every push to main):
- Automatically increments patch version in Cargo.toml and src/service.rs
- Commits version bump with `[version bump]` marker
- Skips if commit already contains `[version bump]` to prevent loops

**Release Workflow** (triggered by version bump commits):
- **Targets**: x86_64 and aarch64 for both Linux and macOS
- **Quality Gates**: Tests and clippy checks must pass
- **Artifacts**: Release binaries uploaded for each architecture
- **Auto-Release**: Creates GitHub releases for new versions

### Deployment Context

The server is designed for deployment as a systemd service on Raspberry Pi nodes, with:
- Cross-compilation support for ARM64
- Systemd service configuration (`goldentooth-mcp.service`)
- Resource limits and security hardening
- stdin/stdout communication model for MCP clients

### Ansible Deployment

Automated deployment is available via Ansible role in `../ansible/`:
- **Role**: `goldentooth.setup_mcp_server` - Downloads latest release, configures service
- **Playbook**: `setup_mcp_server.yaml` - Deploys across cluster nodes
- **Command**: `goldentooth setup_mcp_server` - CLI wrapper for deployment
- **Features**: Architecture detection, automatic updates, systemd management
