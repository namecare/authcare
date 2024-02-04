use async_trait::async_trait;
use sqlx::{query, PgPool, Row};
use thiserror::Error;

use crate::model::user::User;

#[derive(Error, Debug)]
pub enum UserRepositoryError {
    #[error("User not found")]
    UserNotFound,

    #[error("Internal data store error")]
    InternalDbError(#[from] sqlx::Error),
}

#[async_trait]
pub trait UserRepository {
    async fn get(&self, user_id: &uuid::Uuid) -> Result<User, UserRepositoryError>;
    async fn find_by_email(&self, email: &str) -> Result<User, UserRepositoryError>;
    async fn contains_with_email(&self, email: &str) -> Result<bool, UserRepositoryError>;
    async fn add(&self, account: User) -> Result<User, UserRepositoryError>;
    async fn delete(&self, user_id: &uuid::Uuid) -> Result<(), UserRepositoryError>;
}

pub struct DbUserRepository {
    db: PgPool,
}

impl DbUserRepository {
    pub fn new(pool: PgPool) -> DbUserRepository {
        Self { db: pool }
    }
}

#[async_trait]
impl UserRepository for DbUserRepository {
    async fn get(&self, user_id: &uuid::Uuid) -> Result<User, UserRepositoryError> {
        sqlx::query_as!(User, r#"SELECT * FROM auth_user WHERE id = $1"#, user_id)
            .fetch_one(&self.db)
            .await
            .map_err(UserRepositoryError::InternalDbError)
    }

    async fn find_by_email(&self, email: &str) -> Result<User, UserRepositoryError> {
        sqlx::query_as!(User, r#"SELECT * FROM auth_user WHERE email = $1"#, email)
            .fetch_one(&self.db)
            .await
            .map_err(UserRepositoryError::InternalDbError)
    }

    async fn contains_with_email(&self, email: &str) -> Result<bool, UserRepositoryError> {
        let resut: bool = sqlx::query(r#"SELECT EXISTS(SELECT 1 FROM auth_user WHERE email = $1)"#)
            .bind(email)
            .fetch_one(&self.db)
            .await?
            .get(0);

        Ok(resut)
    }

    async fn add(&self, user: User) -> Result<User, UserRepositoryError> {
        let query_result = sqlx::query_as!(
            User,
            r#"INSERT INTO auth_user (id,email,encrypted_password) VALUES ($1, $2, $3) RETURNING *"#,
            user.id,
            user.email,
            user.encrypted_password
        )
            .fetch_one(&self.db)
            .await?;

        Ok(query_result)
    }

    async fn delete(&self, user_id: &uuid::Uuid) -> Result<(), UserRepositoryError> {
        query!("DELETE FROM auth_user WHERE id = $1", user_id)
            .execute(&self.db)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;

    #[sqlx::test]
    async fn check_contains_test(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
        let repo = DbUserRepository::new(pool.clone());
        let account = repo.add(User::mock()).await?;

        let exists = repo.contains_with_email("no@email.com").await?;
        assert_eq!(exists, false);

        let exists = repo
            .contains_with_email(account.email.expect("We have email").as_str())
            .await?;
        assert_eq!(exists, true);
        Ok(())
    }

    #[sqlx::test]
    async fn add_account_test(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
        let repo = DbUserRepository::new(pool.clone());

        let user = repo.add(User::mock()).await.expect("Expect");
        let exists = repo
            .contains_with_email(user.email.expect("We have email").as_str())
            .await
            .expect("123");
        assert_eq!(exists, true);
        Ok(())
    }
}
