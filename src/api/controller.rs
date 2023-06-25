use actix_web::{post, web, HttpResponse, Responder, ResponseError};
use thiserror::Error;
use validator::Validate;

use crate::api::dto::{
    AccessTokenDTO, PasswordGrantParams, RefreshTokenGrantParams, Response, SignUpDTO,
    TokenGrantType, TokenQueryDTO,
};
use crate::config::AppConfig;
use crate::service::auth_service::AuthService;
use crate::model::jwt::{encode_jwt, JWTClaims};
use crate::model::refresh_token::RefreshToken;
use crate::model::user::User;
use crate::service::token_service::TokenService;
use crate::service::user_serivce::UserService;

#[derive(Error, Debug)]
pub enum ControllerError {
    #[error("Internal JWT Extraction error")]
    InternalJWTExtractionError(#[from] actix_web_httpauth::extractors::AuthenticationError<actix_web_httpauth::headers::www_authenticate::bearer::Bearer>),

    #[error("Internal JWT error")]
    InternalJWTError(#[from] jsonwebtoken::errors::Error),
}

impl ResponseError for ControllerError {}

#[post("/auth/signup")]
pub async fn signup_handler(
    dto: web::Json<SignUpDTO>,
    user_service: web::Data<UserService>,
    token_service: web::Data<TokenService>,
) -> impl Responder {
    match dto.validate() {
        Ok(_) => {}
        Err(error) => {
            return HttpResponse::BadRequest().json(Response::fail(error.to_string()));
        }
    };

    let Ok(user) = user_service.create_user(dto.email.clone(), dto.password.clone()).await else {
        return HttpResponse::InternalServerError()
            .json(Response::internal_error());
    };

    let Ok(refresh_token) = token_service.issue_refresh_token(&user).await else {
        return HttpResponse::InternalServerError()
            .json(Response::internal_error());
    };

    let Ok(access_token) = generate_access_token(&user, &refresh_token) else {
        return HttpResponse::InternalServerError()
            .json(Response::internal_error());
    };

    HttpResponse::Ok().json(Response::success(access_token))
}

#[post("/auth/token")]
pub async fn token_password_handler(
    query: web::Query<TokenQueryDTO>,
    dto: web::Json<PasswordGrantParams>,
    auth_service: web::Data<AuthService>,
    token_service: web::Data<TokenService>,
) -> impl Responder {
    //TODO: Add rate limit
    let grant_type = query.0.grant_type;

    if grant_type != TokenGrantType::Password {
        HttpResponse::BadRequest().json(Response::fail("Wrong payload".to_string()));
    }

    match dto.validate() {
        Err(error) => {
            return HttpResponse::BadRequest().json(Response::fail(error.to_string()));
        }
        _ => {}
    };

    let email = dto.email.clone();
    let password = dto.password.clone();

    let Ok(user) = auth_service.authenticate(email, password).await else {
        return HttpResponse::Unauthorized()
            .json(Response::fail("Invalid Credentials".to_string() ));
    };

    let Ok(refresh_token) = token_service.issue_refresh_token(&user).await else {
        return HttpResponse::InternalServerError()
            .json(Response::internal_error());
    };

    let Ok(access_token) = generate_access_token(&user, &refresh_token) else {
        return HttpResponse::InternalServerError()
            .json(Response::internal_error());
    };

    HttpResponse::Ok().json(Response::success(access_token))
}

#[post("/auth/token")]
pub async fn token_refresh_handler(
    query: web::Query<TokenQueryDTO>,
    dto: web::Json<RefreshTokenGrantParams>,
    _auth_service: web::Data<AuthService>,
    token_service: web::Data<TokenService>,
) -> impl Responder {
    let grant_type = query.0.grant_type;

    if grant_type != TokenGrantType::RefreshToken {
        HttpResponse::BadRequest().json(Response::fail("Wrong payload".to_string()));
    }

    let Ok(access_token) = token_service.swap_refresh_token(dto.refresh_token.as_str()).await else {
        return HttpResponse::InternalServerError()
            .json(Response::internal_error());
    };

    HttpResponse::Ok().json(Response::success(access_token))
}

#[post("/auth/signout")]
pub async fn signout_handler(
    _auth_service: web::Data<AuthService>,
    _token_service: web::Data<TokenService>,
    _claims: JWTClaims,
) -> impl Responder {
    HttpResponse::Ok()
}

fn generate_access_token(
    user: &User,
    refresh_token: &RefreshToken,
) -> Result<AccessTokenDTO, ControllerError> {
    let token = refresh_token.token.clone();
    let session_id = refresh_token.session_id;
    let jwt = JWTClaims::new(user.id.to_string(), session_id.to_string());
    let encoded_jwt = encode_jwt(&jwt, AppConfig::jwt_secret())?;

    Ok(AccessTokenDTO::new(
        encoded_jwt,
        jwt.exp,
        token,
        user.into(),
    ))
}
