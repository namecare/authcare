use actix_web::error::BlockingError;
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;
use crate::api::dto::TokenInfoDTO;
use crate::config::AppConfig;
use crate::model::jwt::{decode_jwt, JWTClaims};

use crate::model::user::User;
use crate::model::user_repository::{UserRepository, UserRepositoryError};
use crate::model::refresh_token::RefreshToken;
use crate::model::refresh_token_repository::{RefreshTokenRepository, RefreshTokenRepositoryError};
use crate::model::session::Session;
use crate::model::session_repository::{SessionRepository, SessionRepositoryError};
use crate::utils::crypto::random_secret_token;

#[derive(Error, Debug)]
pub enum TokenServiceError {
    #[error("Refresh Token not found")]
    RefreshTokenNotFound,

    #[error("User not found")]
    UserNotFound,

    #[error("Internal Error")]
    InternalError,

    #[error("Internal data store error")]
    InternalDbError(#[from] RefreshTokenRepositoryError),

    #[error("Internal blocking error")]
    InternalBlockingError(#[from] BlockingError),

    #[error("Internal JWT error")]
    InternalJWTError(#[from] jsonwebtoken::errors::Error),

    #[error("Internal user store error")]
    InternalUserRepositoryError(#[from] UserRepositoryError),

    #[error("Internal session store error")]
    InternalSessionRepositoryError(#[from] SessionRepositoryError),
}

#[derive(Clone)]
pub struct TokenService {
    refresh_token_repository: Arc<dyn RefreshTokenRepository + Send + Sync + 'static>,
    user_repository: Arc<dyn UserRepository + Send + Sync + 'static>,
    session_repository: Arc<dyn SessionRepository + Send + Sync + 'static>,
}

impl TokenService {
    pub fn new(
        refresh_token_repository: Arc<dyn RefreshTokenRepository + Send + Sync + 'static>,
        user_repository: Arc<dyn UserRepository + Send + Sync + 'static>,
        session_repository: Arc<dyn SessionRepository + Send + Sync + 'static>,
    ) -> Self {
        Self {
            refresh_token_repository,
            user_repository,
            session_repository
        }
    }

    pub async fn issue_refresh_token(
        &self,
        user: &User,
    ) -> Result<RefreshToken, TokenServiceError> {
        let session = Session::new(user.id);
        let session = self.session_repository.add(session).await?;

        let refresh_token = self.generate_refresh_token(user.id, session.id);
        self.refresh_token_repository
            .add(refresh_token)
            .await
            .map_err(TokenServiceError::InternalDbError)
    }

    pub async fn swap_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<RefreshToken, TokenServiceError> {
        let refresh_token = self.refresh_token_repository.find(refresh_token).await?;

        let _session = self
            .session_repository
            .get(refresh_token.session_id)
            .await?;
        //TODO: check whether session is still valid?

        let user_uuid = refresh_token.user_id;
        let user = self.user_repository.get(&user_uuid).await?;

        //TODO: check whether the refresh_token is valid (Revoked). If revoked, check the expirational data (issue_at + lifetime). Issue new one if not expired
        //TODO(feat):   check whether the user is banned or not

        let new_refresh_token = self.generate_refresh_token(user.id, refresh_token.session_id);
        self.refresh_token_repository
            .add(new_refresh_token)
            .await
            .map_err(TokenServiceError::InternalDbError)
    }

    pub async fn token_info(&self, access_token: &str) -> Result<TokenInfoDTO, TokenServiceError> {
        let jwt_claims = decode_jwt(access_token, AppConfig::jwt_secret())?;
        let user_uuid = Uuid::parse_str(&jwt_claims.sub).map_err(|e| TokenServiceError::InternalError)?;
        let user = self.user_repository.get(&user_uuid).await?;

        Ok(TokenInfoDTO {
            jwt_claims,
            user: user.into()
        })
    }

    fn generate_refresh_token(&self, user_id: uuid::Uuid, session_id: uuid::Uuid) -> RefreshToken {
        RefreshToken::new(user_id, session_id, random_secret_token(64))
    }
}
