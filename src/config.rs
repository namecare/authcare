use crate::constants::JWT_EXPIRED_IN;

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
}
