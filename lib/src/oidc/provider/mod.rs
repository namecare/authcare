use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod apple;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    #[serde(rename = "iss")]
    pub issuer: Option<String>,

    #[serde(rename = "sub")]
    pub subject: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub gender: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub birthdate: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub zoneinfo: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_verified: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_claims: Option<HashMap<String, serde_json::Value>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
}

/// Struct that contains the user's data returned from the oauth provider
#[derive(Debug, Serialize, Deserialize)]
pub struct UserProvidedData {
    pub emails: Vec<Email>,
    pub metadata: Option<Claims>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Email {
    pub email: String,
    pub verified: bool,
    pub primary: bool,
}
