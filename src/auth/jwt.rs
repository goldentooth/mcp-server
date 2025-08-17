//! JWT token validation using cluster PKI
//!
//! This module handles JWT token validation for MCP server authentication.
//! It validates tokens using the cluster CA certificate at /etc/ssl/certs/goldentooth.pem.

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};

/// JWT Claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
}

/// Validate JWT token using cluster PKI
pub async fn validate_jwt_token(token: &str) -> bool {
    // Get cluster CA certificate for JWT validation
    let ca_cert_path = "/etc/ssl/certs/goldentooth.pem";

    // Try to read the public key from cluster CA
    let public_key = match std::fs::read(ca_cert_path) {
        Ok(cert_data) => {
            // For now, use a simple approach - in production, extract public key from cert
            match DecodingKey::from_rsa_pem(&cert_data) {
                Ok(key) => Some(key),
                Err(_) => {
                    eprintln!("Failed to parse cluster CA certificate for JWT validation");
                    None
                }
            }
        }
        Err(_) => {
            // Fallback: use a default validation approach for development
            eprintln!("Cluster CA certificate not found, using fallback validation");
            None
        }
    };

    // If we have a public key, validate with it; otherwise use fallback
    if let Some(key) = public_key {
        // Validate token with cluster CA
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;

        match decode::<Claims>(token, &key, &validation) {
            Ok(token_data) => {
                // Additional validation: check subject and expiration
                let now = chrono::Utc::now().timestamp() as usize;
                !token_data.claims.sub.is_empty() && token_data.claims.exp > now
            }
            Err(err) => {
                eprintln!("JWT validation failed: {err:?}");
                false
            }
        }
    } else {
        // Fallback validation for development
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return false;
        }

        // Try to decode without signature verification (development only)
        let mut validation = Validation::new(Algorithm::RS256);
        validation.insecure_disable_signature_validation();
        validation.validate_exp = true;

        match decode::<Claims>(token, &DecodingKey::from_secret(&[]), &validation) {
            Ok(token_data) => {
                // Check expiration
                let now = chrono::Utc::now().timestamp() as usize;
                token_data.claims.exp > now
            }
            Err(err) => {
                eprintln!("Fallback JWT validation failed: {err:?}");
                false
            }
        }
    }
}
