use async_trait::async_trait;
use sqlx::PgPool;
use thiserror::Error;

use crate::model::identity::Identity;

#[derive(Error, Debug)]
pub enum IdentityRepositoryError {
    #[error("Internal data store error")]
    InternalDbError(#[from] sqlx::Error),
}

#[async_trait]
pub trait IdentityRepository {
    async fn get(&self, id: u64) -> Result<Identity, IdentityRepositoryError>;
    async fn find(&self, id: &str, provider: &str) -> Result<Identity, IdentityRepositoryError>;
    async fn find_all_by_email(
        &self,
        emails: &[String],
    ) -> Result<Vec<Identity>, IdentityRepositoryError>;
    async fn add(&self, identity: &Identity) -> Result<Identity, IdentityRepositoryError>;
    async fn update(&self, identity: Identity) -> Result<Identity, IdentityRepositoryError>;
    async fn delete(&self, id: u64) -> Result<(), IdentityRepositoryError>;
}

pub struct DbIdentityRepository {
    db: PgPool,
}

impl DbIdentityRepository {
    pub fn new(pool: PgPool) -> DbIdentityRepository {
        Self { db: pool }
    }
}

#[async_trait]
impl IdentityRepository for DbIdentityRepository {
    async fn get(&self, _id: u64) -> Result<Identity, IdentityRepositoryError> {
        todo!()
    }

    async fn find(&self, id: &str, provider: &str) -> Result<Identity, IdentityRepositoryError> {
        sqlx::query_as!(
            Identity,
            r#"SELECT * FROM identity WHERE id = $1 AND provider = $2"#,
            id,
            provider
        )
        .fetch_one(&self.db)
        .await
        .map_err(IdentityRepositoryError::InternalDbError)
    }

    async fn find_all_by_email(
        &self,
        emails: &[String],
    ) -> Result<Vec<Identity>, IdentityRepositoryError> {
        sqlx::query_as!(
            Identity,
            r#"SELECT * FROM identity WHERE email = ANY($1::text[])"#,
            emails
        )
        .fetch_all(&self.db)
        .await
        .map_err(IdentityRepositoryError::InternalDbError)
    }
    async fn add(&self, identity: &Identity) -> Result<Identity, IdentityRepositoryError> {
        let query_result = sqlx::query_as!(
            Identity,
            r#"INSERT INTO identity (id, user_id, identity_data, provider, last_sign_in_at) VALUES ($1, $2, $3, $4, $5) RETURNING *"#,
            identity.id,
            identity.user_id,
            identity.identity_data,
            identity.provider,
            identity.last_sign_in_at
        )
            .fetch_one(&self.db)
            .await?;

        Ok(query_result)
    }

    async fn update(&self, _identity: Identity) -> Result<Identity, IdentityRepositoryError> {
        todo!()
    }

    async fn delete(&self, _id: u64) -> Result<(), IdentityRepositoryError> {
        todo!()
    }
}
