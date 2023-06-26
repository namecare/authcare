use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::model::user::User;
use crate::constants::TOKEN_TYPE;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub struct Response<T: Serialize> {
    status: String,
    data: Option<T>,
}

impl<T: Serialize> Response<T> {
    pub fn success(data: T) -> Response<T> {
        Self {
            status: "success".into(),
            data: Some(data),
        }
    }
}

impl Response<String> {
    pub fn fail(message: std::string::String) -> Response<std::string::String> {
        Self {
            status: "failure".to_string(),
            data: Some(message),
        }
    }

    pub fn internal_error() -> Response<std::string::String> {
        Self::fail("internal error".to_string())
    }
}

#[derive(Debug, Validate, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignUpDTO {
    #[validate(email)]
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserDTO {
    pub id: uuid::Uuid,
    pub email: String,
}

impl From<User> for UserDTO {
    fn from(value: User) -> Self {
        Self {
            id: value.id,
            email: value.email.expect("Let's expect for now"),
        }
    }
}

impl From<&User> for UserDTO {
    fn from(value: &User) -> Self {
        Self {
            id: value.id,
            email: value.email.clone().expect("Let's expect for now"),
        }
    }
}

#[derive(Debug, Validate, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshTokenDTO {
    pub refresh_token: String,
}

#[derive(Debug, Validate, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessTokenDTO {
    pub token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: String,
    pub user: UserDTO,
}

impl AccessTokenDTO {
    pub fn new(token: String, expires_in: i64, refresh_token: String, user: UserDTO) -> Self {
        Self {
            token,
            token_type: TOKEN_TYPE.to_string(),
            expires_in,
            refresh_token,
            user,
        }
    }
}

#[derive(Debug, Validate, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordGrantParams {
    #[validate(email)]
    pub email: String,
    pub password: String,
}

#[derive(Debug, Validate, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshTokenGrantParams {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenQueryDTO {
    pub grant_type: TokenGrantType,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum TokenGrantType {
    Password,
    RefreshToken,
}