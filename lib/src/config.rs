use std::collections::HashMap;
use crate::constants::JWT_EXPIRED_IN;
use lazy_static::lazy_static;

lazy_static! {
    static ref OAUTH_PROVIDERS: HashMap<String, OAuthProviderConfiguration> = build_ouath_providers();
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

    pub fn provider_configuration(issuer_url: &str) -> OAuthProviderConfiguration {
        OAUTH_PROVIDERS.get(issuer_url).expect("Expect oAuth configuration for now").clone()
    }
}

#[derive(Clone, serde::Deserialize)]
pub struct OAuthProviderConfiguration {
    pub issuer: String,
    pub client_id: String,
    pub secret: Option<String>,
    pub redirect_uri: Option<String>,
}

impl OAuthProviderConfiguration {
    fn new(issuer: &str, client_id: &str) -> Self {
        Self {
            issuer: issuer.to_string(),
            client_id: client_id.to_string(),
            secret: None,
            redirect_uri: None,
        }
    }
}
fn build_ouath_providers() -> HashMap<String, OAuthProviderConfiguration> {
    let mut hash_map = HashMap::new();

    if let Ok(issuer) = std::env::var("OAUTH_APPLE_ISSUER") {
        let Ok(client_id) = std::env::var("OAUTH_APPLE_CLIENT_ID") else { panic!("Missing OAUTH_APPLE_CLIENT_ID env") };
        hash_map.insert(issuer.clone(), OAuthProviderConfiguration::new(&issuer, &client_id));
    };

    hash_map
}



