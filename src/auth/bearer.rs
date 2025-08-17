//! Bearer token extraction from HTTP Authorization headers
//!
//! This module handles extracting Bearer tokens from HTTP Authorization headers
//! according to RFC 6750 (OAuth 2.0 Bearer Token Usage).

/// Extract bearer token from Authorization header
///
/// Parses the Authorization header value and extracts the Bearer token.
/// Supports both "Bearer" and "bearer" (case-insensitive).
///
/// # Arguments
/// * `auth_header` - The Authorization header value (e.g., "Bearer token123")
///
/// # Returns
/// * `Some(token)` if a valid Bearer token is found
/// * `None` if no Bearer token is present or token is empty
///
/// # Examples
/// ```
/// use goldentooth_mcp::auth::bearer::extract_bearer_token;
///
/// assert_eq!(extract_bearer_token("Bearer abc123"), Some("abc123"));
/// assert_eq!(extract_bearer_token("bearer lowercase"), Some("lowercase"));
/// assert_eq!(extract_bearer_token("Bearer "), None);
/// assert_eq!(extract_bearer_token("Basic auth"), None);
/// ```
pub fn extract_bearer_token(auth_header: &str) -> Option<&str> {
    if auth_header.to_lowercase().starts_with("bearer ") {
        let token = auth_header[7..].trim_start();
        if token.is_empty() { None } else { Some(token) }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_bearer_token() {
        // Valid Bearer tokens
        assert_eq!(extract_bearer_token("Bearer abc123"), Some("abc123"));
        assert_eq!(extract_bearer_token("bearer lowercase"), Some("lowercase"));
        assert_eq!(
            extract_bearer_token("Bearer   whitespace"),
            Some("whitespace")
        );

        // Invalid cases
        assert_eq!(extract_bearer_token("Bearer "), None);
        assert_eq!(extract_bearer_token("Basic auth"), None);
        assert_eq!(extract_bearer_token(""), None);
        assert_eq!(extract_bearer_token("Bearer"), None);
        assert_eq!(extract_bearer_token("NotBearer token"), None);
    }
}
