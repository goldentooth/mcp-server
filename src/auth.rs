use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use oauth2::{
    AccessToken, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl,
    RefreshToken, Scope, TokenResponse, TokenUrl, basic::BasicClient, reqwest::async_http_client,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{
    env,
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
                .unwrap_or_else(|_| "https://auth.goldentooth.net:9091".to_string()),
            client_id: env::var("OAUTH_CLIENT_ID")
                .unwrap_or_else(|_| "goldentooth-mcp".to_string()),
            client_secret: env::var("OAUTH_CLIENT_SECRET").unwrap_or_else(|_| "".to_string()),
            redirect_uri: env::var("OAUTH_REDIRECT_URI")
                .unwrap_or_else(|_| "https://mcp.goldentooth.net/callback".to_string()),
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
    pub fn new(config: AuthConfig) -> Self {
        Self {
            config,
            client: Client::new(),
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
        );

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
        validation.set_audience(&[&self.config.client_id]);

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
        let oauth_client = self
            .oauth_client
            .as_ref()
            .ok_or(AuthError::ClientNotInitialized)?;

        let token_result = oauth_client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(async_http_client)
            .await
            .map_err(|e| AuthError::InvalidConfig(format!("Token exchange failed: {}", e)))?;

        Ok(token_result.access_token().clone())
    }

    pub async fn refresh_token(&self, refresh_token: &str) -> AuthResult<AccessToken> {
        let oauth_client = self
            .oauth_client
            .as_ref()
            .ok_or(AuthError::ClientNotInitialized)?;

        let token_result = oauth_client
            .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
            .request_async(async_http_client)
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
            "https://auth.goldentooth.net:9091"
        );
        assert_eq!(config.client_id, "goldentooth-mcp");
        assert_eq!(config.redirect_uri, "https://mcp.goldentooth.net/callback");
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
