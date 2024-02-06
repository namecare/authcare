use crate::model::user::User;
use crate::oidc::provider::UserProvidedData;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sqlx::types::JsonValue;
use std::collections::HashMap;

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, sqlx::FromRow, Serialize, Clone)]
pub struct Identity {
    pub id: String,
    pub user_id: uuid::Uuid,
    pub email: Option<String>,
    pub identity_data: JsonValue,
    pub provider: String,
    pub last_sign_in_at: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

impl Identity {
    pub fn new(user: &User, provider: &str, identity_data: HashMap<String, Value>) -> Self {
        let provider_id = identity_data.get("sub").expect("Expect sub").to_string();
        let email = identity_data
            .get("email")
            .expect("Expect email")
            .to_string();

        let mut map: Map<String, Value> = Map::new();

        for item in identity_data.iter() {
            map.insert(item.0.clone(), item.1.clone());
        }

        Identity {
            id: provider_id,
            user_id: user.id,
            email: Some(email),
            identity_data: JsonValue::Object(map),
            provider: provider.to_string(),
            last_sign_in_at: None,
            created_at: None,
            updated_at: None,
        }
    }

    pub fn new_from_provider(
        user: &User,
        provider: &str,
        provider_data: &UserProvidedData,
    ) -> Self {
        let meta = provider_data.metadata.as_ref().expect("Expect meta");
        let provider_id = meta.subject.as_ref().expect("Expect sub");

        let email = &provider_data.emails[0].email;

        Identity {
            id: provider_id.clone(),
            user_id: user.id,
            email: Some(email.clone()),
            identity_data: serde_json::to_value(meta).expect("Expect map"),
            provider: provider.to_string(),
            last_sign_in_at: None,
            created_at: None,
            updated_at: None,
        }
    }
}
