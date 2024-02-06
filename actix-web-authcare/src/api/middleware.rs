use crate::api::controller::ControllerError;
use actix_web::{dev::Payload, FromRequest, HttpRequest};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use authcare::config::AppConfig;
use authcare::model::jwt::{decode_jwt, JWTClaims};
use std::future::Future;
use std::pin::Pin;

pub struct JWTClaimsDTO(pub JWTClaims);

impl FromRequest for JWTClaimsDTO {
    type Error = ControllerError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let req = req.clone();
        Box::pin(async move {
            let bearer = BearerAuth::extract(&req).await?;
            let bearer_token = bearer.token();
            let decoded_token = decode_jwt(bearer_token, AppConfig::jwt_secret())?;
            Ok(JWTClaimsDTO(decoded_token))
        })
    }
}
