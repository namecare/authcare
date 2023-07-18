use chrono::prelude::*;

use serde::{Deserialize, Serialize};

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, sqlx::FromRow, Serialize, Clone)]
pub struct RefreshToken {
    pub id: Option<i64>,
    pub token: String,
    pub user_id: uuid::Uuid,
    pub session_id: uuid::Uuid,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl RefreshToken {
    pub fn new(user_id: uuid::Uuid, session_id: uuid::Uuid, token: String) -> Self {
        let now = Utc::now();

        Self {
            id: None, // Use random id when creating a new instance
            token: token,
            user_id: user_id,
            session_id: session_id,
            revoked: false,
            created_at: now,
            updated_at: now,
        }
    }
}

impl RefreshToken {
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn is_revoke(&self) -> bool {
        self.revoked
    }
}
