use crate::auth::{AuthService, Claims};
use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct AuthenticatedStream<T> {
    inner: T,
    claims: Option<Claims>,
    auth_headers: HashMap<String, String>,
}

impl<T> AuthenticatedStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            claims: None,
            auth_headers: HashMap::new(),
        }
    }

    pub fn with_claims(inner: T, claims: Claims) -> Self {
        Self {
            inner,
            claims: Some(claims),
            auth_headers: HashMap::new(),
        }
    }

    pub fn set_auth_header(&mut self, key: String, value: String) {
        self.auth_headers.insert(key, value);
    }

    pub fn get_claims(&self) -> Option<&Claims> {
        self.claims.as_ref()
    }

    pub fn get_auth_header(&self, key: &str) -> Option<&String> {
        self.auth_headers.get(key)
    }
}

impl<T> AsyncRead for AuthenticatedStream<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for AuthenticatedStream<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub async fn authenticate_http_request(
    auth_service: &AuthService,
    headers: &HashMap<String, String>,
) -> Result<Option<Claims>, String> {
    if let Some(auth_header) = headers.get("authorization") {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            match auth_service.validate_token(token).await {
                Ok(claims) => Ok(Some(claims)),
                Err(e) => Err(format!("Authentication failed: {}", e)),
            }
        } else {
            Err("Invalid authorization header format".to_string())
        }
    } else {
        Err("Missing authorization header".to_string())
    }
}

// Mock HTTP header parser for demonstration
pub fn parse_http_headers(request: &str) -> HashMap<String, String> {
    let mut headers = HashMap::new();

    for line in request.lines().skip(1) {
        // Skip the request line
        if line.is_empty() {
            break; // End of headers
        }

        if let Some((key, value)) = line.split_once(':') {
            headers.insert(key.trim().to_lowercase(), value.trim().to_string());
        }
    }

    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_headers() {
        let request = "GET / HTTP/1.1\r
Host: example.com\r
Authorization: Bearer token123\r
Content-Type: application/json\r
\r
";
        let headers = parse_http_headers(request);

        assert_eq!(headers.get("host"), Some(&"example.com".to_string()));
        assert_eq!(
            headers.get("authorization"),
            Some(&"Bearer token123".to_string())
        );
        assert_eq!(
            headers.get("content-type"),
            Some(&"application/json".to_string())
        );
    }

    #[tokio::test]
    async fn test_authenticated_stream() {
        use tokio::io::duplex;

        let (client, server) = duplex(1024);
        let auth_stream = AuthenticatedStream::new(server);

        assert!(auth_stream.get_claims().is_none());
        drop(client); // Close the client side
    }
}
