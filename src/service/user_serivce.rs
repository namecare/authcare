use std::collections::HashMap;
use crate::model::user::User;
use crate::model::user_repository::{UserRepository, UserRepositoryError};
use crate::service::auth_service::AuthServiceError;
use crate::utils::crypto::hash_password;
use actix_web::error::BlockingError;
use actix_web::web;
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use serde_json::map::Values;
use serde_json::Value;
use thiserror::Error;
use crate::model::identity::Identity;
use crate::model::identity_repository::{IdentityRepository, IdentityRepositoryError};

#[derive(Error, Debug)]
pub enum UserServiceError {
    #[error("User exist")]
    UserExists,

    #[error("Account not found")]
    AccountNotFound,

    #[error("Internal user data store error")]
    InternalDbError(#[from] UserRepositoryError),

    #[error("Internal identity data store error")]
    InternalIdentityDbError(#[from] IdentityRepositoryError),


    #[error("Internal blocking error")]
    InternalBlockingError(#[from] BlockingError),

}

#[derive(Clone)]
pub struct UserService {
    user_repository: Arc<dyn UserRepository + Send + Sync>,
    identity_repository: Arc<dyn IdentityRepository + Send + Sync>,
}

impl UserService {
    pub fn new(user_repository: Arc<dyn UserRepository + Send + Sync>, identity_repository: Arc<dyn IdentityRepository + Send + Sync>) -> Self {
        UserService {
            user_repository: user_repository.clone(),
            identity_repository: identity_repository.clone()
        }
    }

    pub async fn create_user(
        &self,
        email: String,
        password: String,
    ) -> Result<User, UserServiceError> {
        let exists = self.user_repository.contains_with_email(&email).await?;
        if exists == true {
            return Err(UserServiceError::UserExists);
        }

        let hashed_password = web::block(move || hash_password(password.as_str())).await?;

        let user = User::new(email, hashed_password);
        let user = self.user_repository.add(user).await?;
        let identity_data: HashMap<String, serde_json::Value> = HashMap::from([
            ("sub".to_string(), user.id.to_string().into()),
            ("email".to_string(), user.email.clone().expect("For now we explect email").into()),
        ]);

        let idenity = Identity::new(&user, "email", identity_data);
        self.identity_repository.add(&idenity).await?;

        Ok(user)
    }

    pub async fn find_user(&self, email: &str) -> Result<User, UserServiceError> {
        self.user_repository
            .find_by_email(email)
            .await
            .map_err(UserServiceError::InternalDbError)
    }
}
