use actix_web::error::BlockingError;
use actix_web::web;
use sqlx::{Pool, Postgres};
use std::sync::Arc;

use thiserror::Error;

use crate::model::user::{User, UserError};
use crate::model::user_repository::{UserRepository, UserRepositoryError};

#[derive(Error, Debug)]
pub enum AuthServiceError {
    #[error("User Exists")]
    UserExists,

    #[error("Account not found")]
    AccountNotFound,

    #[error("Invalid Credentials")]
    InvalidCredentials,

    #[error("Internal account")]
    InternalAccountError(#[from] UserError),

    #[error("Internal data store error")]
    InternalDbError(#[from] UserRepositoryError),

    #[error("Internal blocking error")]
    InternalBlockingError(#[from] BlockingError),
}

#[derive(Clone)]
pub struct AuthService {
    account_repository: Arc<dyn UserRepository + Send + Sync>,
    db: Pool<Postgres>,
}

impl AuthService {
    pub fn new(
        account_repository: Arc<dyn UserRepository + Send + Sync>,
        db: Pool<Postgres>,
    ) -> Self {
        AuthService {
            account_repository: account_repository.clone(),
            db: db.clone(),
        }
    }

    pub async fn authenticate(
        &self,
        email: String,
        password: String,
    ) -> Result<User, AuthServiceError> {
        let Ok(user) = self.account_repository.find_by_email(email.as_str()).await else {
            return Err(AuthServiceError::AccountNotFound)
        };

        let user = web::block(move || -> Result<User, AuthServiceError> {
            let Ok(authenticated) = user.authenticate(password.as_str()) else {
                return Err(AuthServiceError::InvalidCredentials);
            };

            if authenticated {
                return Ok(user);
            } else {
                return Err(AuthServiceError::InvalidCredentials);
            }
        })
        .await??;

        Ok(user)
    }
}
