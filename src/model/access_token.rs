use crate::constants::TOKEN_TYPE;
use crate::model::refresh_token::{RefreshToken};
use crate::model::user::User;

#[derive(Clone, Debug)]
pub struct AccessToken {
    pub token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: RefreshToken,
    pub user: User,
}

impl AccessToken {
    pub fn new(token: String, expires_in: i64, refresh_token: RefreshToken, user: User) -> Self {
        Self {
            token,
            expires_in,
            token_type: TOKEN_TYPE.to_string(),
            refresh_token,
            user,
        }
    }
}

//pub struct IdTokenClien