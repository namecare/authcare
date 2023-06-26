use crate::model::user::User;
use crate::model::user_repository::{UserRepository, UserRepositoryError};
use crate::service::auth_service::AuthServiceError;
use crate::utils::crypto::hash_password;
use actix_web::error::BlockingError;
use actix_web::web;
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AccountServiceError {
    #[error("Account not found")]
    AccountNotFound,

    #[error("Internal data store error")]
    InternalDbError(#[from] UserRepositoryError),

    #[error("Internal blocking error")]
    InternalBlockingError(#[from] BlockingError),
}

#[derive(Clone)]
pub struct UserService {
    user_repository: Arc<dyn UserRepository + Send + Sync>,
}

impl UserService {
    pub fn new(user_repository: Arc<dyn UserRepository + Send + Sync>) -> Self {
        UserService {
            user_repository: user_repository.clone()
        }
    }

    pub async fn create_user(
        &self,
        email: String,
        password: String,
    ) -> Result<User, AuthServiceError> {
        let exists = self.user_repository.contains_with_email(&email).await?;
        if exists == true {
            return Err(AuthServiceError::UserExists);
        }

        let hashed_password = web::block(move || hash_password(password.as_str())).await?;

        let account = User::new(email, hashed_password);

        Ok(self.user_repository.add(account).await?)
    }

    pub async fn find_user(&self, email: &str) -> Result<User, AccountServiceError> {
        self.user_repository
            .find_by_email(email)
            .await
            .map_err(AccountServiceError::InternalDbError)
    }
}
