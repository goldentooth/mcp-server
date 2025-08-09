//! Core type system for Goldentooth MCP Server
//!
//! This module provides compile-time guarantees for correctness by making
//! illegal states unrepresentable. Instead of runtime validation, we use
//! the type system to ensure protocol compliance, stream separation, and
//! proper error handling.

pub mod error_codes;
pub mod io_streams;
pub mod log_level;
pub mod mcp_message;

pub use error_codes::*;
pub use io_streams::*;
pub use log_level::*;
pub use mcp_message::*;
