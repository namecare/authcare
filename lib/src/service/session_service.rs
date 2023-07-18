use crate::model::user::User;
use crate::model::user_repository::{UserRepository, UserRepositoryError};
use crate::service::auth_service::AuthServiceError;
use crate::utils::crypto::hash_password;
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use thiserror::Error;
use crate::model::session_repository::{SessionRepository, SessionRepositoryError};

#[derive(Error, Debug)]
pub enum SessionServiceError {
    #[error("Session not found")]
    SessionNotFound,

    #[error("Internal data store error")]
    InternalDbError(#[from] SessionRepositoryError),
}

#[derive(Clone)]
pub struct SessionService {
    session_repository: Arc<dyn SessionRepository + Send + Sync + 'static>,
}

impl SessionService {
    pub fn new(session_repository: Arc<dyn SessionRepository + Send + Sync + 'static>) -> Self {
        SessionService {
            session_repository,
        }
    }

    pub async fn revoke_session(&self, session_id: &uuid::Uuid) -> Result<(), SessionServiceError> {
        self.session_repository.delete(session_id).await?;
        Ok(())
    }

}
