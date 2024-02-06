use crate::constants::JWT_EXPIRED_IN;
use lazy_static::lazy_static;
use std::collections::HashMap;
use crate::oidc::oidc::{OidcProvider};

lazy_static! {
    static ref OAUTH_PROVIDERS: HashMap<String, OAuthProviderConfiguration> =
        build_ouath_providers();
}

#[derive(Debug, Clone)]
pub struct AppConfig;

impl AppConfig {
    pub fn database_url() -> String {
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set")
    }

    pub fn jwt_expires_in() -> i64 {
        std::env::var("JWT_EXPIRED_IN")
            .map(|val| val.parse().unwrap_or(JWT_EXPIRED_IN))
            .unwrap_or(JWT_EXPIRED_IN)
    }

    pub fn jwt_secret() -> String {
        std::env::var("JWT_SECRET").expect("JWT_SECRET must be set")
    }

    pub fn provider_configuration(provider: &OidcProvider) -> Option<&'static OAuthProviderConfiguration> {
        OAUTH_PROVIDERS
            .get(provider.name())
            // .map(|v| v.clone())
    }
}

#[derive(Clone, serde::Deserialize)]
pub struct OAuthProviderConfiguration {
    pub client_id: String,
    pub secret: Option<String>,
    pub redirect_uri: Option<String>,
}

impl OAuthProviderConfiguration {
    fn new(client_id: &str, secret: Option<String>) -> Self {
        Self {
            client_id: client_id.to_string(),
            secret: secret,
            redirect_uri: None,
        }
    }
}
fn build_ouath_providers() -> HashMap<String, OAuthProviderConfiguration> {
    let mut hash_map = HashMap::new();

    if let Ok(client_id) = std::env::var("OAUTH_APPLE_CLIENT_ID") {
        hash_map.insert(
            OidcProvider::Apple.name().to_string(),
            OAuthProviderConfiguration::new(&client_id, None),
        );
    };

    if let Ok(client_id) = std::env::var("OAUTH_GOOGLE_CLIENT_ID") {
        let Ok(secret) = std::env::var("OAUTH_GOOGLE_SECRET") else {
            panic!("Missing OAUTH_GOOGLE_SECRET env")
        };

        hash_map.insert(
            OidcProvider::Google.name().to_string(),
            OAuthProviderConfiguration::new(&client_id, Some(secret)),
        );
    };

    hash_map
}
