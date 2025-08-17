# MCP Server Test Suite

This directory contains the comprehensive test suite for the Goldentooth MCP Server.

## Test Organization

Tests are organized by module to match the source code structure:

```
tests/
├── CLAUDE.md                           # This overview
├── common/                             # Shared test utilities
│   ├── mod.rs                         # Test module declarations
│   └── test_helpers.rs                # Common test helper functions
│
├── auth/                              # Authentication tests
│   └── authentication_security.rs    # JWT/OAuth security tests
│
├── transport/                         # Transport layer tests
│   ├── http_transport.rs             # HTTP transport functionality
│   ├── http_transport_test.rs         # HTTP transport edge cases
│   ├── http_integration.rs           # HTTP integration tests
│   ├── sse_stream_management.rs      # Server-Sent Events tests
│   └── transport_parity.rs           # stdio/HTTP parity tests
│
├── tools/                             # Tool execution tests
│   ├── tool_execution.rs             # Basic tool execution
│   ├── type_safe_tool_execution.rs   # Type safety tests
│   └── cluster_tools_integration.rs  # Cluster tool integration
│
└── [other test files]                 # Root-level integration tests
```

## Test Categories

### Unit Tests
- Individual module functionality
- Type safety and validation
- Error handling patterns
- Input validation

### Integration Tests
- Transport parity (stdio vs HTTP)
- Authentication flows
- Tool execution against real cluster
- Protocol compliance

### Security Tests
- JWT token validation
- Authentication bypass prevention
- Origin header validation
- DNS rebinding protection

### Performance Tests
- Response time validation (<5s for cluster operations)
- Connection handling and limits
- Memory usage patterns
- Concurrent request handling

## Running Tests

### All Tests
```bash
cargo test
```

### Specific Module Tests
```bash
# Authentication tests
cargo test auth::

# Transport tests
cargo test transport::

# Tool tests
cargo test tools::
```

### Integration Tests (requires cluster access)
```bash
cargo test --features integration
```

### Security Tests
```bash
cargo test --test authentication_security
```

## Test Helpers

### `common/test_helpers.rs`
- `ResponseAssertions` - HTTP response validation
- `AuthTestHelper` - JWT token generation for testing
- Mock server utilities
- Test data generation

### Environment Setup
Tests may require:
- Cluster access for integration tests
- JWT signing keys for auth tests
- Network ports for HTTP tests
- Temporary directories for file operations

## Test Requirements

### Transport Parity
Both stdio and HTTP transports must:
- Provide identical functionality
- Handle errors consistently
- Return same response formats
- Support all available tools

### Authentication Testing
- Valid/invalid JWT tokens
- Expired token handling
- Missing Authorization headers
- Malformed Bearer tokens
- Origin header validation

### Tool Testing
- Type-safe argument validation
- Error handling for unreachable nodes
- Response format compliance
- Timeout handling
- Security validation

## Continuous Integration

All tests run automatically on:
- Pull request creation
- Push to main branch
- Release creation
- Nightly builds

### Test Requirements for CI
- All tests must pass
- No ignored tests without justification
- Coverage requirements met
- Performance benchmarks satisfied

## Development Guidelines

### Adding New Tests
1. Place tests in appropriate module directory
2. Use existing test helpers when possible
3. Follow naming conventions
4. Include both positive and negative test cases
5. Document complex test scenarios

### Test Naming Conventions
- `test_` prefix for all test functions
- Descriptive names indicating what is being tested
- Group related tests in modules
- Use `#[should_panic]` for expected failure tests

### Mock Data and Fixtures
- Store test data in `tests/fixtures/` if needed
- Use realistic but safe test values
- Avoid hardcoded secrets or sensitive data
- Generate dynamic test data when possible
