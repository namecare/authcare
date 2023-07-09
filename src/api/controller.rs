use actix_web::{get, post, web, HttpResponse, Responder, ResponseError, HttpRequest, FromRequest};
use actix_web::web::Payload;
use thiserror::Error;
use validator::Validate;

use crate::api::dto::{AccessTokenDTO, PasswordGrantParams, RefreshTokenDTO, RefreshTokenGrantParams, Response, SignUpDTO, TokenGrantParams, TokenGrantType, TokenInfoQueryDTO, TokenQueryDTO};
use crate::config::AppConfig;
use crate::service::auth_service::AuthService;
use crate::model::jwt::{decode_jwt, encode_jwt, JWTClaims};
use crate::model::refresh_token::RefreshToken;
use crate::model::user::User;
use crate::service::session_service::SessionService;
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

    HttpResponse::Ok().json(access_token)
}

#[post("/auth/token")]
pub async fn token_handler(
    query: web::Query<TokenQueryDTO>,
    dto: web::Json<TokenGrantParams>,
    auth_service: web::Data<AuthService>,
    token_service: web::Data<TokenService>,
) -> impl Responder {
    //TODO: Add rate limit

    match query.grant_type {
        TokenGrantType::Password => return token_password_handler(dto.0.into(), auth_service, token_service).await,
        TokenGrantType::RefreshToken => return token_refresh_handler(dto.0.into(), token_service).await
    }
}

#[get("/auth/token")]
pub async fn token_info_handler(
    query: web::Query<TokenInfoQueryDTO>,
    token_service: web::Data<TokenService>,
) -> impl Responder {

    let access_token = query.0.access_token;
    let Ok(token_info) = token_service.token_info(&access_token).await else {
        return HttpResponse::Unauthorized()
            .json(Response::fail("Invalid token".to_string() ));
    };

    HttpResponse::Ok().json(token_info)
}

#[post("/auth/signout")]
pub async fn signout_handler(
    session_service: web::Data<SessionService>,
    claims: JWTClaims,
) -> impl Responder {
    let Ok(sid) = uuid::Uuid::parse_str(claims.sid.as_str()) else {
        return HttpResponse::Unauthorized()
            .json(Response::fail("Invalid JWT claims".to_string() ));
    };

    let Ok(()) = session_service.revoke_session(&sid).await else {
        return HttpResponse::InternalServerError()
            .json(Response::internal_error());
    };

    HttpResponse::Ok().json(Response::success("Have a good one!"))
}

// Private

async fn token_password_handler(
    dto: PasswordGrantParams,
    auth_service: web::Data<AuthService>,
    token_service: web::Data<TokenService>,
) -> HttpResponse {
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
            .json(Response::fail("Invalid Credentials".to_string()))
    };

    let Ok(refresh_token) = token_service.issue_refresh_token(&user).await else {
        return HttpResponse::InternalServerError()
            .json(Response::internal_error());
    };

    let Ok(access_token) = generate_access_token(&user, &refresh_token) else {
        return HttpResponse::InternalServerError()
            .json(Response::internal_error());
    };

    HttpResponse::Ok().json(access_token)
}

async fn token_refresh_handler(
    dto: RefreshTokenGrantParams,
    token_service: web::Data<TokenService>,
) -> HttpResponse {
    let Ok(access_token) = token_service.swap_refresh_token(dto.refresh_token.as_str()).await else {
        return HttpResponse::InternalServerError()
            .json(Response::internal_error());
    };

    HttpResponse::Ok().json(RefreshTokenDTO::from(access_token))
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
