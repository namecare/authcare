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
}

#[derive(Clone)]
pub struct AuthService {
    account_repository: Arc<dyn UserRepository + Send + Sync + 'static>,
}

impl AuthService {
    pub fn new(account_repository: Arc<dyn UserRepository + Send + Sync + 'static>) -> Self {
        AuthService { account_repository }
    }

    pub async fn authenticate(
        &self,
        email: String,
        password: String,
    ) -> Result<User, AuthServiceError> {
        let Ok(user) = self.account_repository.find_by_email(email.as_str()).await else {
            return Err(AuthServiceError::AccountNotFound);
        };

        use tokio::task;

        let user = task::spawn_blocking(move || {
            let Ok(authenticated) = user.authenticate(password.as_str()) else {
                return Err(AuthServiceError::InvalidCredentials);
            };

            if authenticated {
                return Ok(user);
            } else {
                return Err(AuthServiceError::InvalidCredentials);
            }
        })
        .await
        .expect("Expect complete")?;

        Ok(user)
    }
}
