use crate::oidc::oidc::{OidcError};
use crate::oidc::provider::{Claims, Email, UserProvidedData};
use openidconnect::core::{CoreGenderClaim, CoreIdTokenVerifier, CoreJsonWebKeyType, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm};
use openidconnect::{NonceVerifier};
use std::collections::HashMap;
use std::str::FromStr;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::oidc::serde_string_bool;

pub const ISSUER_APPLE: &'static str = "https://appleid.apple.com";

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct AdditionalClaims {
    #[serde(deserialize_with = "serde_string_bool::deserialize")]
    pub is_private_email: bool,
    pub auth_time: Option<DateTime<Utc>>,
}

impl openidconnect::AdditionalClaims for AdditionalClaims {}

pub type IdToken = openidconnect::IdToken<
    AdditionalClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
>;

pub fn parse_apple_id_token_claims<N: NonceVerifier>(verifier: &CoreIdTokenVerifier, nonce_verifier: N, id_token: &str) -> Result<UserProvidedData, OidcError> {
    let token = IdToken::from_str(id_token)?;
    let claims = token.claims(verifier, nonce_verifier)?;

    let email = Email {
        email: claims.email().expect("Expect email").to_string(),
        verified: true,
        primary: true,
    };

    let add_claims = claims.additional_claims();

    let mut custom_claims: HashMap<String, serde_json::Value> = HashMap::new();
    custom_claims.insert(
        "is_private_email".to_string(),
        serde_json::to_value(add_claims.is_private_email)?,
    );

    if let Some(auth_time) = &add_claims.auth_time {
        custom_claims.insert("auth_time".to_string(), serde_json::to_value(auth_time)?);
    }

    let metadata = Claims {
        issuer: Some(claims.issuer().to_string()),
        subject: claims.subject().to_string().into(),
        aud: None,
        iat: None,
        exp: None,
        name: None,
        family_name: None,
        given_name: None,
        middle_name: None,
        nickname: None,
        preferred_username: None,
        profile: None,
        picture: None,
        website: None,
        gender: None,
        birthdate: None,
        zone_info: None,
        locale: None,
        updated_at: None,
        email: claims.email().map(|v| v.to_string()),
        email_verified: Some(true),
        phone: None,
        custom_claims: if custom_claims.is_empty() {
            None
        } else {
            Some(custom_claims)
        },
        phone_verified: None,
    };

    let data = UserProvidedData {
        emails: vec![email],
        metadata: Some(metadata),
    };

    Ok(data)
}
