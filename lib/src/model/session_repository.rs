use async_trait::async_trait;
use sqlx::PgPool;
use thiserror::Error;

use crate::model::session::Session;

#[derive(Error, Debug)]
pub enum SessionRepositoryError {
    #[error("Internal data store error")]
    InternalDbError(#[from] sqlx::Error),
}

#[async_trait]
pub trait SessionRepository {
    async fn get(&self, id: uuid::Uuid) -> Result<Session, SessionRepositoryError>;
    async fn add(&self, session: Session) -> Result<Session, SessionRepositoryError>;
    async fn update(&self, session: Session) -> Result<Session, SessionRepositoryError>;
    async fn delete(&self, id: &uuid::Uuid) -> Result<(), SessionRepositoryError>;
}

pub struct DbSessionRepository {
    db: PgPool,
}

impl DbSessionRepository {
    pub fn new(pool: PgPool) -> DbSessionRepository {
        Self { db: pool }
    }
}

#[async_trait]
impl SessionRepository for DbSessionRepository {
    async fn get(&self, id: uuid::Uuid) -> Result<Session, SessionRepositoryError> {
        let query_result =
            sqlx::query_as!(Session, r#"SELECT * FROM auth_session WHERE id = $1"#, id)
                .fetch_one(&self.db)
                .await?;

        Ok(query_result)
    }

    async fn add(&self, session: Session) -> Result<Session, SessionRepositoryError> {
        let query_result = sqlx::query_as!(
            Session,
            r#"INSERT INTO auth_session (id, user_id) VALUES ($1, $2) RETURNING *"#,
            session.id,
            session.user_id
        )
        .fetch_one(&self.db)
        .await?;

        Ok(query_result)
    }

    async fn update(&self, _session: Session) -> Result<Session, SessionRepositoryError> {
        todo!()
    }

    async fn delete(&self, id: &uuid::Uuid) -> Result<(), SessionRepositoryError> {
        let _ = sqlx::query!("DELETE FROM auth_session WHERE id = $1", id)
            .execute(&self.db)
            .await?;

        Ok(())
    }
}
