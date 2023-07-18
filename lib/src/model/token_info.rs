use crate::model::jwt::JWTClaims;
use crate::model::user::User;

#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub jwt_claims: JWTClaims,
    pub user: User
}