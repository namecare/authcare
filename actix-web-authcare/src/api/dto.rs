use authcare::constants::TOKEN_TYPE;
use authcare::model::jwt::JWTClaims;
use authcare::model::refresh_token::RefreshToken;
use authcare::model::token_info::TokenInfo;
use authcare::model::user::User;
use serde::{Deserialize, Serialize};
use validator::Validate;
use authcare::oidc::oidc::OidcProvider;

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
    pub is_super_user: bool,
}

impl From<User> for UserDTO {
    fn from(value: User) -> Self {
        Self {
            id: value.id,
            email: value.email.expect("Let's expect for now"),
            is_super_user: value.is_super_user.unwrap_or(false),
        }
    }
}

impl From<&User> for UserDTO {
    fn from(value: &User) -> Self {
        Self {
            id: value.id,
            email: value.email.clone().expect("Let's expect for now"),
            is_super_user: value.is_super_user.unwrap_or(false),
        }
    }
}

#[derive(Debug, Validate, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshTokenDTO {
    pub refresh_token: String,
}

impl From<RefreshToken> for RefreshTokenDTO {
    fn from(value: RefreshToken) -> Self {
        Self {
            refresh_token: value.token,
        }
    }
}

#[derive(Debug, Validate, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessTokenDTO {
    pub token: String,
    pub token_type: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub refresh_token: String,
    pub user: UserDTO,
}

impl AccessTokenDTO {
    pub fn new(
        token: String,
        expires_at: i64,
        issued_at: i64,
        refresh_token: String,
        user: UserDTO,
    ) -> Self {
        Self {
            token,
            token_type: TOKEN_TYPE.to_string(),
            issued_at,
            expires_at,
            refresh_token,
            user,
        }
    }
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
    IdToken,
}

#[derive(Debug, Validate, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenGrantParams {
    // email & pass
    pub email: Option<String>,
    pub password: Option<String>,

    // refresh token
    pub refresh_token: Option<String>,

    // id token
    pub token: Option<String>,
    pub provider: Option<OidcProvider>,
    pub issuer: Option<String>,
}

#[derive(Debug, Validate)]
pub struct PasswordGrantParams {
    #[validate(email)]
    pub email: String,
    pub password: String,
}

impl From<TokenGrantParams> for PasswordGrantParams {
    fn from(value: TokenGrantParams) -> Self {
        Self {
            email: value.email.expect("Expect email"),
            password: value.password.expect("Expect password"),
        }
    }
}

#[derive(Debug)]
pub struct RefreshTokenGrantParams {
    pub refresh_token: String,
}

impl From<TokenGrantParams> for RefreshTokenGrantParams {
    fn from(value: TokenGrantParams) -> Self {
        Self {
            refresh_token: value.refresh_token.expect("Expect refresh token"),
        }
    }
}

#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct IdTokenGrantParams {
    pub token: String,
    pub provider: OidcProvider,
}

impl From<TokenGrantParams> for IdTokenGrantParams {
    fn from(value: TokenGrantParams) -> Self {
        Self {
            token: value.token.expect("Expect token"),
            provider: value.provider.expect("Expect provider"),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenInfoQueryDTO {
    pub access_token: String,
}

#[derive(Debug, Serialize)]
pub struct TokenInfoDto {
    pub jwt_claims: JWTClaims,
    pub user: UserDTO,
}

impl From<TokenInfo> for TokenInfoDto {
    fn from(value: TokenInfo) -> Self {
        Self {
            jwt_claims: value.jwt_claims,
            user: value.user.into(),
        }
    }
}
