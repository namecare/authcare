use crate::oidc::oidc::{OidcError};
use crate::oidc::provider::{Claims, Email, UserProvidedData};
use openidconnect::core::{CoreGenderClaim, CoreIdTokenVerifier, CoreJsonWebKeyType, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm};
use openidconnect::{EmptyAdditionalClaims, NonceVerifier};
use std::str::FromStr;

pub const ISSUER_GOOGLE: &'static str = "https://accounts.google.com";

pub type IdToken = openidconnect::IdToken<
    EmptyAdditionalClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
>;

pub fn parse_google_id_token_claims<N: NonceVerifier>(verifier: &CoreIdTokenVerifier, nonce_verifier: N, id_token: &str) -> Result<UserProvidedData, OidcError> {
    let token = IdToken::from_str(id_token)?;
    let claims = token.claims(verifier, nonce_verifier)?;

    let email = Email {
        email: claims.email().expect("Expect email").to_string(),
        verified: true,
        primary: true,
    };

    let name = match claims.name() {
        Some(name) => name.get(None).map(|v| v.to_string()),
        None => None
    };

    let picture = match claims.picture() {
        Some(name) => name.get(None).map(|v| v.to_string()),
        None => None
    };

    let metadata = Claims {
        issuer: Some(claims.issuer().to_string()),
        subject: claims.subject().to_string().into(),
        aud: None,
        iat: None,
        exp: None,
        name: name,
        family_name: None,
        given_name: None,
        middle_name: None,
        nickname: None,
        preferred_username: None,
        profile: None,
        picture,
        website: None,
        gender: None,
        birthdate: None,
        zone_info: None,
        locale: None,
        updated_at: None,
        email: claims.email().map(|v| v.to_string()),
        email_verified: claims.email_verified(),
        phone: None,
        custom_claims: None,
        phone_verified: None,
    };

    let data = UserProvidedData {
        emails: vec![email],
        metadata: Some(metadata),
    };

    Ok(data)
}
