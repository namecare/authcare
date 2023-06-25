use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::utils::crypto::compare_hash_and_password;

#[derive(Error, Debug)]
pub enum UserError {
    #[error("Authentication failed")]
    AuthenticationFailed(AuthenticationFailedErrorReason),

    #[error("Internal blocking error")]
    InternalBlockingError(#[from] tokio::task::JoinError),
}

#[derive(Debug)]
pub enum AuthenticationFailedErrorReason {
    NoPassword,
    IncorrectPassword,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, sqlx::FromRow, Serialize, Clone)]
pub struct User {
    pub id: uuid::Uuid,
    pub email: Option<String>,
    pub encrypted_password: Option<String>,
    pub is_super_user: Option<bool>,
    pub banned_until: Option<DateTime<Utc>>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

impl User {
    pub fn new(email: String, encrypted_password: String) -> User {
        Self {
            id: uuid::Uuid::new_v4(),
            email: Some(email),
            encrypted_password: Some(encrypted_password),
            banned_until: None,
            is_super_user: Some(false),
            confirmed_at: None,
            created_at: None,
            updated_at: None,
        }
    }

    pub fn mock() -> User {
        Self {
            id: uuid::Uuid::new_v4(),
            email: Some("test@email.com".to_string()),
            encrypted_password: Some("1a2/4z".to_string()),
            is_super_user: Some(false),
            banned_until: None,
            confirmed_at: None,
            created_at: None,
            updated_at: None,
        }
    }
}

impl User {
    pub fn authenticate(&self, password: &str) -> Result<bool, UserError> {
        let Some(pass) = &self.encrypted_password else {
            return Err(UserError::AuthenticationFailed(AuthenticationFailedErrorReason::NoPassword));
        };

        Ok(compare_hash_and_password(pass.as_str(), password))
    }
}
