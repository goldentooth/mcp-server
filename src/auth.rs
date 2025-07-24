use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use oauth2::{
    AccessToken, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl,
    RefreshToken, Scope, TokenResponse, TokenUrl, basic::BasicClient, reqwest::async_http_client,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;

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
            client_secret: env::var("OAUTH_CLIENT_SECRET")
                .unwrap_or_else(|_| "changeme".to_string()), // Should be set via env
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

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<JwkKey>,
}

#[derive(Debug, Serialize, Deserialize)]
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
}

impl AuthService {
    pub fn new(config: AuthConfig) -> Self {
        Self {
            config,
            client: Client::new(),
            oauth_client: None,
        }
    }

    pub async fn initialize(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let discovery = self.discover_oidc_config().await?;

        let oauth_client = BasicClient::new(
            ClientId::new(self.config.client_id.clone()),
            Some(ClientSecret::new(self.config.client_secret.clone())),
            AuthUrl::new(discovery.authorization_endpoint)?,
            Some(TokenUrl::new(discovery.token_endpoint)?),
        )
        .set_redirect_uri(RedirectUrl::new(self.config.redirect_uri.clone())?);

        self.oauth_client = Some(oauth_client);
        Ok(())
    }

    pub async fn discover_oidc_config(&self) -> Result<OidcDiscovery, Box<dyn std::error::Error>> {
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            self.config.authelia_base_url
        );
        let response = self.client.get(&discovery_url).send().await?;
        let discovery: OidcDiscovery = response.json().await?;
        Ok(discovery)
    }

    pub async fn get_jwks(&self) -> Result<JwksResponse, Box<dyn std::error::Error>> {
        let discovery = self.discover_oidc_config().await?;
        let response = self.client.get(&discovery.jwks_uri).send().await?;
        let jwks: JwksResponse = response.json().await?;
        Ok(jwks)
    }

    pub async fn validate_token(&self, token: &str) -> Result<Claims, Box<dyn std::error::Error>> {
        // Decode the JWT header to get the key ID
        let header = decode_header(token)?;
        let kid = header.kid.ok_or("JWT missing key ID")?;

        // Get JWKS and find the matching key
        let jwks = self.get_jwks().await?;
        let jwk = jwks
            .keys
            .iter()
            .find(|key| key.kid == kid)
            .ok_or("No matching key found in JWKS")?;

        // Convert JWK to PEM format for RSA public key
        let decoding_key = self.jwk_to_decoding_key(jwk)?;

        // Set up validation parameters
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.config.authelia_base_url]);
        validation.set_audience(&[&self.config.client_id]);

        // Decode and validate the token
        let token_data = decode::<Claims>(token, &decoding_key, &validation)?;
        Ok(token_data.claims)
    }

    fn jwk_to_decoding_key(&self, jwk: &JwkKey) -> Result<DecodingKey, Box<dyn std::error::Error>> {
        // Create RSA public key from JWK components (already base64url encoded)
        let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)?;
        Ok(key)
    }

    pub fn get_authorization_url(&self) -> Result<(String, CsrfToken), Box<dyn std::error::Error>> {
        let oauth_client = self
            .oauth_client
            .as_ref()
            .ok_or("OAuth client not initialized")?;

        let (auth_url, csrf_token) = oauth_client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("groups".to_string()))
            .url();

        Ok((auth_url.to_string(), csrf_token))
    }

    pub async fn exchange_code_for_token(
        &self,
        code: &str,
    ) -> Result<AccessToken, Box<dyn std::error::Error>> {
        let oauth_client = self
            .oauth_client
            .as_ref()
            .ok_or("OAuth client not initialized")?;

        let token_result = oauth_client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(async_http_client)
            .await?;

        Ok(token_result.access_token().clone())
    }

    pub async fn refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<AccessToken, Box<dyn std::error::Error>> {
        let oauth_client = self
            .oauth_client
            .as_ref()
            .ok_or("OAuth client not initialized")?;

        let token_result = oauth_client
            .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
            .request_async(async_http_client)
            .await?;

        Ok(token_result.access_token().clone())
    }

    pub fn requires_auth(&self) -> bool {
        // Authentication is required if client secret is not the default placeholder
        self.config.client_secret != "changeme"
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
        let config = AuthConfig::default();
        let auth_service = AuthService::new(config);
        assert!(!auth_service.requires_auth()); // Should be false with default "changeme" secret
    }

    #[test]
    fn test_requires_auth() {
        let mut config = AuthConfig::default();
        config.client_secret = "real-secret".to_string();
        let auth_service = AuthService::new(config);
        assert!(auth_service.requires_auth());
    }
}
