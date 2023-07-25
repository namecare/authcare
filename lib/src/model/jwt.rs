use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::constants::{JWT_AUD_CLAIN, JWT_EXPIRED_IN, JWT_ISS_CLAIN};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWTClaims {
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
    pub sub: String, //User id
    pub sid: String, //Session id
}

impl JWTClaims {
    pub fn new(sub: String, sid: String) -> Self {
        let now = Utc::now();
        Self {
            aud: JWT_AUD_CLAIN.to_string(),
            exp: (now + Duration::minutes(JWT_EXPIRED_IN)).timestamp(),
            iat: now.timestamp(),
            iss: JWT_ISS_CLAIN.to_string(),
            sub,
            sid,
        }
    }
}

/// Create a json web token (JWT)
pub fn encode_jwt(
    jwt_claims: &JWTClaims,
    secret: String,
) -> Result<String, jsonwebtoken::errors::Error> {
    let encoding_key = EncodingKey::from_secret(secret.as_bytes());
    jsonwebtoken::encode(&Header::default(), jwt_claims, &encoding_key)
}

/// Decode a json web token (JWT)
pub fn decode_jwt(
    token: &str,
    secret: String,
) -> Result<JWTClaims, jsonwebtoken::errors::Error> {
    decode_jwt_with_validator(token, secret, &Validation::default())
}

pub(crate) fn decode_jwt_with_validator(
    token: &str,
    secret: String,
    validator: &Validation,
) -> Result<JWTClaims, jsonwebtoken::errors::Error> {
    let decoding_key = DecodingKey::from_secret(secret.as_bytes());
    jsonwebtoken::decode::<JWTClaims>(token, &decoding_key, validator).map(|data| data.claims)
}
