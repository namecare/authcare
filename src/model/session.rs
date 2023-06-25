use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Session {
    pub fn new(user_id: Uuid) -> Session {
        let now = Utc::now();

        Self {
            id: uuid::Uuid::new_v4(),
            user_id,
            created_at: now,
            updated_at: now,
        }
    }
}
