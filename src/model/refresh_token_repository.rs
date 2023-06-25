use async_trait::async_trait;
use sqlx::PgPool;
use thiserror::Error;

use crate::model::refresh_token::RefreshToken;

#[derive(Error, Debug)]
pub enum RefreshTokenRepositoryError {
    #[error("Internal data store error")]
    InternalDbError(#[from] sqlx::Error),
}

#[async_trait]
pub trait RefreshTokenRepository {
    async fn get(&self, id: u64) -> Result<RefreshToken, RefreshTokenRepositoryError>;
    async fn find(&self, token: &str) -> Result<RefreshToken, RefreshTokenRepositoryError>;
    async fn add(&self, token: RefreshToken) -> Result<RefreshToken, RefreshTokenRepositoryError>;
    async fn update(
        &self,
        token: RefreshToken,
    ) -> Result<RefreshToken, RefreshTokenRepositoryError>;
    async fn delete(&self, id: u64) -> Result<(), RefreshTokenRepositoryError>;
}

pub struct DbRefreshTokenRepository {
    db: PgPool,
}

impl DbRefreshTokenRepository {
    pub fn new(pool: PgPool) -> DbRefreshTokenRepository {
        Self { db: pool }
    }
}

#[async_trait]
impl RefreshTokenRepository for DbRefreshTokenRepository {
    async fn get(&self, _id: u64) -> Result<RefreshToken, RefreshTokenRepositoryError> {
        todo!()
    }

    async fn find(&self, token: &str) -> Result<RefreshToken, RefreshTokenRepositoryError> {
        sqlx::query_as!(
            RefreshToken,
            r#"SELECT * FROM auth_refresh_token WHERE token = $1"#,
            token
        )
        .fetch_one(&self.db)
        .await
        .map_err(RefreshTokenRepositoryError::InternalDbError)
    }

    async fn add(&self, token: RefreshToken) -> Result<RefreshToken, RefreshTokenRepositoryError> {
        let query_result = sqlx::query_as!(
            RefreshToken,
            r#"INSERT INTO auth_refresh_token (token, user_id, session_id) VALUES ($1, $2, $3) RETURNING *"#,
            token.token,
            token.user_id,
            token.session_id
        )
            .fetch_one(&self.db)
            .await?;

        Ok(query_result)
    }

    async fn update(
        &self,
        token: RefreshToken,
    ) -> Result<RefreshToken, RefreshTokenRepositoryError> {
        let query_result = sqlx::query_as!(
            RefreshToken,
            r#"UPDATE auth_refresh_token SET token = $1 RETURNING *"#,
            token.token
        )
        .fetch_one(&self.db)
        .await?;

        Ok(query_result)
    }

    async fn delete(&self, _id: u64) -> Result<(), RefreshTokenRepositoryError> {
        todo!()
    }
}
