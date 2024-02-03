use actix_web::{get, post, web, HttpResponse, Responder, ResponseError, delete};
use thiserror::Error;
use validator::Validate;
use authcare::config::AppConfig;
use authcare::model::jwt::{encode_jwt, JWTClaims};
use authcare::model::refresh_token::RefreshToken;
use authcare::model::user::User;
use authcare::oidc::oidc::OidcClient;
use authcare::service::auth_service::AuthService;
use authcare::service::session_service::SessionService;
use authcare::service::token_service::TokenService;
use authcare::service::user_serivce::UserService;
use crate::api::dto::{AccessTokenDTO, IdTokenGrantParams, PasswordGrantParams, RefreshTokenGrantParams, Response, SignUpDTO, TokenGrantParams, TokenGrantType, TokenInfoDto, TokenInfoQueryDTO, TokenQueryDTO};
use crate::api::middleware::JWTClaimsDTO;

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
    user_service: web::Data<UserService>,
) -> impl Responder {
    //TODO: Add rate limit

    match query.grant_type {
        TokenGrantType::Password => return token_password_handler(dto.0.into(), auth_service, token_service).await,
        TokenGrantType::RefreshToken => return token_refresh_handler(dto.0.into(), token_service, user_service).await,
        TokenGrantType::IdToken => return id_token_handler(dto.0.into(), token_service, user_service).await,
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

    let dto: TokenInfoDto = token_info.into();
    HttpResponse::Ok().json(dto)
}

#[post("/auth/signout")]
pub async fn signout_handler(
    session_service: web::Data<SessionService>,
    claims: JWTClaimsDTO,
) -> impl Responder {
    let Ok(sid) = uuid::Uuid::parse_str(claims.0.sid.as_str()) else {
        return HttpResponse::Unauthorized()
            .json(Response::fail("Invalid JWT claims".to_string() ));
    };

    let Ok(()) = session_service.revoke_session(&sid).await else {
        return HttpResponse::InternalServerError()
            .json(Response::internal_error());
    };

    HttpResponse::Ok().json(Response::success("Have a good one!"))
}

#[delete("/auth/user")]
pub async fn delete_user_handler(
    user_service: web::Data<UserService>,
    claims: JWTClaimsDTO,
) -> impl Responder {
    let Ok(uid) = uuid::Uuid::parse_str(claims.0.sub.as_str()) else {
        return HttpResponse::Unauthorized()
            .json(Response::fail("Invalid JWT claims".to_string() ));
    };

    let Ok(()) = user_service.delete_user(&uid).await else {
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
    user_service: web::Data<UserService>,
) -> HttpResponse {
    let Ok(refresh_token) = token_service.swap_refresh_token(dto.refresh_token.as_str()).await else {
        return HttpResponse::InternalServerError()
            .json(Response::internal_error());
    };

    let Ok(user) = user_service.get_user(&refresh_token.user_id).await else {
        return HttpResponse::InternalServerError()
            .json(Response::internal_error());
    };

    let Ok(access_token) = generate_access_token(&user, &refresh_token) else {
        return HttpResponse::InternalServerError()
            .json(Response::internal_error());
    };

    HttpResponse::Ok().json(access_token)
}

async fn id_token_handler(
    dto: IdTokenGrantParams,
    token_service: web::Data<TokenService>,
    user_service: web::Data<UserService>
) -> HttpResponse {
    let Ok(provider) = extract_provider(&dto).await else {
        return HttpResponse::InternalServerError()
            .json(Response::internal_error());
    };

    let Ok(claims) = provider.verify(dto.token.as_str(), None) else {
        return HttpResponse::Unauthorized()
            .json(Response::fail("Invalid Credentials".to_string()))
    };

    let Ok(user) = user_service.create_user_from_external_identity(&claims, &dto.provider).await else {
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

async fn extract_provider(dto: &IdTokenGrantParams) -> Result<OidcClient, ControllerError> {
    if dto.provider == "apple" || dto.issuer == "https://appleid.apple.com" {
        let external_configuration = AppConfig::provider_configuration(&dto.issuer);
        let oid_client = OidcClient::new(external_configuration.issuer.as_str(), external_configuration.client_id.as_str()).await;
        return Ok(oid_client);
    }

    panic!("We only support apple")
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
        jwt.iat,
        token,
        user.into(),
    ))
}
