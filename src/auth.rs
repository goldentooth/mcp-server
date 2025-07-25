use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use oauth2::{
    AccessToken, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, HttpRequest,
    HttpResponse, RedirectUrl, RefreshToken, RequestTokenError, Scope, TokenResponse, TokenUrl,
    basic::BasicClient,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("OIDC discovery failed: {0}")]
    DiscoveryFailed(#[from] reqwest::Error),
    #[error("JWT validation failed: {0}")]
    JwtValidation(#[from] jsonwebtoken::errors::Error),
    #[error("OAuth client not initialized")]
    ClientNotInitialized,
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("JWKS key not found: {0}")]
    JwksKeyNotFound(String),
    #[error("Certificate error: {0}")]
    CertificateError(String),
}

pub type AuthResult<T> = Result<T, AuthError>;

#[derive(Debug, Clone)]
struct CachedData<T> {
    data: T,
    cached_at: Instant,
    ttl: Duration,
}

impl<T> CachedData<T> {
    fn new(data: T, ttl: Duration) -> Self {
        Self {
            data,
            cached_at: Instant::now(),
            ttl,
        }
    }

    fn is_valid(&self) -> bool {
        self.cached_at.elapsed() < self.ttl
    }
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub authelia_base_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            authelia_base_url: env::var("AUTHELIA_BASE_URL")
                .unwrap_or_else(|_| "https://auth.services.goldentooth.net".to_string()),
            client_id: env::var("OAUTH_CLIENT_ID")
                .unwrap_or_else(|_| "goldentooth-mcp".to_string()),
            client_secret: env::var("OAUTH_CLIENT_SECRET").unwrap_or_else(|_| "".to_string()),
            redirect_uri: env::var("OAUTH_REDIRECT_URI")
                .unwrap_or_else(|_| "https://mcp.services.goldentooth.net/callback".to_string()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
    pub aud: String,
    pub email: Option<String>,
    pub groups: Option<Vec<String>>,
    pub preferred_username: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<JwkKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkKey {
    pub kty: String,
    pub kid: String,
    pub n: String,
    pub e: String,
    #[serde(rename = "use")]
    pub key_use: Option<String>,
    pub alg: Option<String>,
}

#[derive(Clone)]
pub struct AuthService {
    config: AuthConfig,
    client: Client,
    oauth_client: Option<BasicClient>,
    discovery_cache: Arc<RwLock<Option<CachedData<OidcDiscovery>>>>,
    jwks_cache: Arc<RwLock<Option<CachedData<JwksResponse>>>>,
}

impl AuthService {
    // Custom HTTP client that uses our configured reqwest client with cluster CA
    async fn custom_http_client(
        client: Client,
        request: HttpRequest,
    ) -> Result<
        HttpResponse,
        RequestTokenError<
            oauth2::reqwest::Error<reqwest::Error>,
            oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
        >,
    > {
        // Convert oauth2::http::Method to reqwest::Method
        let method = match request.method.as_str() {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "DELETE" => reqwest::Method::DELETE,
            "HEAD" => reqwest::Method::HEAD,
            "OPTIONS" => reqwest::Method::OPTIONS,
            "PATCH" => reqwest::Method::PATCH,
            _ => {
                return Err(RequestTokenError::Other(
                    "Unsupported HTTP method".to_string(),
                ));
            }
        };

        let mut req_builder = client.request(method, request.url.as_str());

        // Add headers
        for (name, value) in request.headers {
            if let Some(header_name) = name {
                req_builder = req_builder.header(header_name.as_str(), value.to_str().unwrap());
            }
        }

        // Add body if present
        if !request.body.is_empty() {
            req_builder = req_builder.body(request.body);
        }

        let response = req_builder
            .send()
            .await
            .map_err(oauth2::reqwest::Error::Reqwest)
            .map_err(RequestTokenError::Request)?;

        let status_code = response.status();
        let headers = response.headers().clone();
        let body = response
            .bytes()
            .await
            .map_err(oauth2::reqwest::Error::Reqwest)
            .map_err(RequestTokenError::Request)?;

        // Convert reqwest types to oauth2::http types
        let oauth_status = oauth2::http::StatusCode::from_u16(status_code.as_u16())
            .map_err(|_| RequestTokenError::Other("Invalid status code".to_string()))?;

        let mut oauth_headers = oauth2::http::HeaderMap::new();
        for (name, value) in headers.iter() {
            if let (Ok(header_name), Ok(header_value)) = (
                oauth2::http::HeaderName::from_bytes(name.as_str().as_bytes()),
                oauth2::http::HeaderValue::from_bytes(value.as_bytes()),
            ) {
                oauth_headers.insert(header_name, header_value);
            }
        }

        Ok(HttpResponse {
            status_code: oauth_status,
            headers: oauth_headers,
            body: body.to_vec(),
        })
    }

    pub fn new(config: AuthConfig) -> Self {
        println!("🔧 AUTH: Initializing AuthService with config:");
        println!("   - Authelia Base URL: {}", config.authelia_base_url);
        println!("   - Client ID: {}", config.client_id);
        if config.client_secret.len() > 16 {
            println!(
                "   - Client Secret: {}...{}",
                &config.client_secret[..8],
                &config.client_secret[config.client_secret.len() - 8..]
            );
        } else if !config.client_secret.is_empty() {
            println!(
                "   - Client Secret: {}...",
                &config.client_secret[..config.client_secret.len().min(8)]
            );
        } else {
            println!("   - Client Secret: (empty)");
        }
        println!("   - Redirect URI: {}", config.redirect_uri);

        // Configure HTTP client with custom certificate trust
        let mut client_builder = Client::builder().use_rustls_tls();

        // Load the cluster CA certificate if it exists
        const CLUSTER_CA_PATH: &str = "/etc/ssl/certs/goldentooth.pem";
        match fs::read_to_string(CLUSTER_CA_PATH) {
            Ok(ca_cert_pem) => {
                println!(
                    "🔒 AUTH: Found cluster CA certificate at {}",
                    CLUSTER_CA_PATH
                );
                match reqwest::Certificate::from_pem(ca_cert_pem.as_bytes()) {
                    Ok(ca_cert) => {
                        client_builder = client_builder.add_root_certificate(ca_cert);
                        println!("✅ AUTH: Successfully loaded cluster CA certificate");
                    }
                    Err(e) => {
                        println!("❌ AUTH: Failed to parse cluster CA certificate: {}", e);
                    }
                }
            }
            Err(e) => {
                println!(
                    "⚠️ AUTH: Cluster CA certificate not found at {}: {}",
                    CLUSTER_CA_PATH, e
                );
            }
        }

        // For internal cluster communication, accept self-signed certificates
        // This is safe because we're only communicating within our own cluster
        println!(
            "🔓 AUTH: Configuring TLS to accept self-signed certificates for internal cluster communication"
        );
        client_builder = client_builder
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .tls_built_in_root_certs(true);

        let client = client_builder.build().unwrap_or_else(|e| {
            println!("❌ AUTH: Failed to build HTTP client: {}", e);
            Client::new()
        });

        Self {
            config,
            client,
            oauth_client: None,
            discovery_cache: Arc::new(RwLock::new(None)),
            jwks_cache: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn initialize(&mut self) -> AuthResult<()> {
        let discovery = self.discover_oidc_config().await?;

        let oauth_client = BasicClient::new(
            ClientId::new(self.config.client_id.clone()),
            Some(ClientSecret::new(self.config.client_secret.clone())),
            AuthUrl::new(discovery.authorization_endpoint.clone())
                .map_err(|e| AuthError::InvalidConfig(format!("Invalid auth URL: {}", e)))?,
            Some(
                TokenUrl::new(discovery.token_endpoint.clone())
                    .map_err(|e| AuthError::InvalidConfig(format!("Invalid token URL: {}", e)))?,
            ),
        )
        .set_redirect_uri(
            RedirectUrl::new(self.config.redirect_uri.clone())
                .map_err(|e| AuthError::InvalidConfig(format!("Invalid redirect URI: {}", e)))?,
        )
        .set_auth_type(oauth2::AuthType::RequestBody); // Use client_secret_post instead of client_secret_basic

        println!("🔧 AUTH: Configured OAuth client with client_secret_post authentication method");
        self.oauth_client = Some(oauth_client);
        Ok(())
    }

    pub async fn discover_oidc_config(&self) -> AuthResult<OidcDiscovery> {
        // Check cache first
        {
            let cache = self.discovery_cache.read().await;
            if let Some(cached) = cache.as_ref() {
                if cached.is_valid() {
                    return Ok(cached.data.clone());
                }
            }
        }

        // Fetch from server
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            self.config.authelia_base_url
        );
        let response = self.client.get(&discovery_url).send().await?;
        let discovery: OidcDiscovery = response.json().await?;

        // Cache the result (5 minutes TTL)
        {
            let mut cache = self.discovery_cache.write().await;
            *cache = Some(CachedData::new(discovery.clone(), Duration::from_secs(300)));
        }

        Ok(discovery)
    }

    pub async fn get_jwks(&self) -> AuthResult<JwksResponse> {
        // Check cache first
        {
            let cache = self.jwks_cache.read().await;
            if let Some(cached) = cache.as_ref() {
                if cached.is_valid() {
                    return Ok(cached.data.clone());
                }
            }
        }

        // Fetch from server
        let discovery = self.discover_oidc_config().await?;
        let response = self.client.get(&discovery.jwks_uri).send().await?;
        let jwks: JwksResponse = response.json().await?;

        // Cache the result (1 hour TTL)
        {
            let mut cache = self.jwks_cache.write().await;
            *cache = Some(CachedData::new(jwks.clone(), Duration::from_secs(3600)));
        }

        Ok(jwks)
    }

    pub async fn validate_token(&self, token: &str) -> AuthResult<Claims> {
        // Decode the JWT header to get the key ID
        let header = decode_header(token)?;
        let kid = header
            .kid
            .ok_or_else(|| AuthError::InvalidConfig("JWT missing key ID".to_string()))?;

        // Get JWKS and find the matching key
        let jwks = self.get_jwks().await?;
        let jwk = jwks
            .keys
            .iter()
            .find(|key| key.kid == kid)
            .ok_or_else(|| AuthError::JwksKeyNotFound(kid.clone()))?;

        // Convert JWK to decoding key
        let decoding_key = self.jwk_to_decoding_key(jwk)?;

        // Set up validation parameters - use actual issuer from discovery
        let discovery = self.discover_oidc_config().await?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&discovery.issuer]);
        // Don't require audience for client_credentials tokens - they often don't have one
        validation.validate_aud = false;

        // Decode and validate the token
        let token_data = decode::<Claims>(token, &decoding_key, &validation)?;
        Ok(token_data.claims)
    }

    fn jwk_to_decoding_key(&self, jwk: &JwkKey) -> AuthResult<DecodingKey> {
        // Create RSA public key from JWK components (already base64url encoded)
        let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)?;
        Ok(key)
    }

    pub fn get_authorization_url(&self) -> AuthResult<(String, CsrfToken)> {
        let oauth_client = self
            .oauth_client
            .as_ref()
            .ok_or(AuthError::ClientNotInitialized)?;

        let (auth_url, csrf_token) = oauth_client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("groups".to_string()))
            .url();

        Ok((auth_url.to_string(), csrf_token))
    }

    pub async fn exchange_code_for_token(&self, code: &str) -> AuthResult<AccessToken> {
        let code_preview = if code.len() > 40 {
            format!("{}...{}", &code[..20], &code[code.len() - 20..])
        } else {
            code.to_string()
        };
        println!(
            "🔄 AUTH: Starting token exchange for authorization code: {}",
            code_preview
        );

        let oauth_client = self
            .oauth_client
            .as_ref()
            .ok_or(AuthError::ClientNotInitialized)?;

        println!("✅ AUTH: OAuth client is initialized");

        // Get the discovery config to show token endpoint
        match self.discover_oidc_config().await {
            Ok(discovery) => {
                println!("🌐 AUTH: Token endpoint: {}", discovery.token_endpoint);
            }
            Err(e) => {
                println!("⚠️ AUTH: Could not fetch OIDC discovery config: {}", e);
            }
        }

        // Create a closure that captures our HTTP client
        let client = self.client.clone();
        let http_client = |request: HttpRequest| {
            let client = client.clone();
            Box::pin(async move {
                println!("📤 AUTH: Making token exchange request:");
                println!("   - Method: {}", request.method);
                println!("   - URL: {}", request.url);
                println!("   - Headers: {:?}", request.headers);
                println!("   - Body: {}", String::from_utf8_lossy(&request.body));

                let result = Self::custom_http_client(client, request).await;

                match &result {
                    Ok(response) => {
                        println!("📥 AUTH: Token exchange response:");
                        println!("   - Status: {:?}", response.status_code);
                        println!("   - Headers: {:?}", response.headers);
                        println!("   - Body: {}", String::from_utf8_lossy(&response.body));
                    }
                    Err(e) => {
                        println!("❌ AUTH: Token exchange HTTP error: {:?}", e);
                    }
                }

                result
            })
        };

        println!("🚀 AUTH: Initiating OAuth2 token exchange...");
        let token_result = oauth_client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(http_client)
            .await
            .map_err(|e| {
                println!("💥 AUTH: OAuth2 token exchange failed with error: {:?}", e);
                AuthError::InvalidConfig(format!("Token exchange failed: {:?}", e))
            })?;

        let token_secret = token_result.access_token().secret();
        let token_preview = if token_secret.len() > 40 {
            format!(
                "{}...{}",
                &token_secret[..20],
                &token_secret[token_secret.len() - 20..]
            )
        } else {
            token_secret.to_string()
        };
        println!(
            "🎉 AUTH: Token exchange successful! Access token: {}",
            token_preview
        );

        Ok(token_result.access_token().clone())
    }

    pub async fn refresh_token(&self, refresh_token: &str) -> AuthResult<AccessToken> {
        let oauth_client = self
            .oauth_client
            .as_ref()
            .ok_or(AuthError::ClientNotInitialized)?;

        // Create a closure that captures our HTTP client
        let client = self.client.clone();
        let http_client = |request: HttpRequest| {
            let client = client.clone();
            Box::pin(async move { Self::custom_http_client(client, request).await })
        };

        let token_result = oauth_client
            .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
            .request_async(http_client)
            .await
            .map_err(|e| AuthError::InvalidConfig(format!("Token refresh failed: {}", e)))?;

        Ok(token_result.access_token().clone())
    }

    pub fn requires_auth(&self) -> bool {
        // Authentication is required if we have a client secret
        !self.config.client_secret.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_config_defaults() {
        let config = AuthConfig::default();
        assert_eq!(
            config.authelia_base_url,
            "https://auth.services.goldentooth.net"
        );
        assert_eq!(config.client_id, "goldentooth-mcp");
        assert_eq!(
            config.redirect_uri,
            "https://mcp.services.goldentooth.net/callback"
        );
    }

    #[test]
    fn test_auth_service_creation() {
        // Set a test secret for this test
        unsafe {
            std::env::set_var("OAUTH_CLIENT_SECRET", "test-secret");
        }
        let config = AuthConfig::default();
        let auth_service = AuthService::new(config);
        assert!(auth_service.requires_auth());
        unsafe {
            std::env::remove_var("OAUTH_CLIENT_SECRET");
        }
    }

    #[test]
    fn test_requires_auth() {
        let config = AuthConfig {
            authelia_base_url: "https://auth.test.com".to_string(),
            client_id: "test-client".to_string(),
            client_secret: "real-secret".to_string(),
            redirect_uri: "https://test.com/callback".to_string(),
        };
        let auth_service = AuthService::new(config);
        assert!(auth_service.requires_auth());
    }

    #[test]
    fn test_requires_auth_empty_secret() {
        let config = AuthConfig {
            authelia_base_url: "https://auth.test.com".to_string(),
            client_id: "test-client".to_string(),
            client_secret: "".to_string(),
            redirect_uri: "https://test.com/callback".to_string(),
        };
        let auth_service = AuthService::new(config);
        assert!(!auth_service.requires_auth());
    }
}
