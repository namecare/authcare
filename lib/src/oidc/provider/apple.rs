use std::collections::HashMap;
use openidconnect::core::CoreGenderClaim;
use openidconnect::IdTokenClaims;
use crate::oidc::oidc::{AdditionalClaims, OidcError};
use crate::oidc::provider::{Claims, Email, UserProvidedData};

pub fn parse_apple_id_token_claims(claims: &IdTokenClaims<AdditionalClaims, CoreGenderClaim>) -> Result<UserProvidedData, OidcError> {
    let email = Email {
        email: claims.email().expect("Expect email").to_string(),
        verified: true,
        primary: true,
    };

    let add_claims = claims.additional_claims();

    let mut custom_claims: HashMap<String, serde_json::Value> = HashMap::new();
    custom_claims.insert("is_private_email".to_string(), serde_json::to_value(add_claims.is_private_email)?);

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
        zoneinfo: None,
        locale: None,
        updated_at: None,
        email: claims.email().map(|v| v.to_string()),
        email_verified: Some(true),
        phone: None,
        provider_id: claims.subject().to_string().into(),
        custom_claims: if custom_claims.is_empty() { None } else { Some(custom_claims) },
        full_name: None,
        avatar_url: None,
        phone_verified: None,
        slug: None,
        user_name: None,
    };

    let data = UserProvidedData {
        emails: vec![email],
        metadata: Some(metadata)
    };

    Ok(data)
}