//#![allow(dead_code)]

use actix_web::middleware::Logger;
use actix_web::{web, App, HttpServer};
use dotenv::dotenv;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;

use crate::service::auth_service::AuthService;
use crate::service::token_service::TokenService;
use crate::service::user_serivce::UserService;
use crate::config::AppConfig;
use crate::model::identity_repository::DbIdentityRepository;
use crate::model::refresh_token_repository::DbRefreshTokenRepository;
use crate::model::session_repository::DbSessionRepository;
use crate::model::user_repository::DbUserRepository;
use crate::service::session_service::SessionService;

mod api;
mod config;
mod constants;
mod model;
mod service;
mod utils;
mod oidc;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "debug");
    env_logger::init();

    dotenv().ok();

    let pool = match PgPoolOptions::new()
        .max_connections(10)
        .connect(AppConfig::database_url().as_str())
        .await
    {
        Ok(pool) => {
            println!("✅Connection to the database is successful!");
            pool
        }
        Err(err) => {
            println!("🔥 Failed to connect to the database: {:?}", err);
            std::process::exit(1);
        }
    };

    println!("🚀 Server started successfully");

    let refresh_token_repo = Arc::new(DbRefreshTokenRepository::new(pool.clone()));
    let account_repo = Arc::new(DbUserRepository::new(pool.clone()));
    let session_repo = Arc::new(DbSessionRepository::new(pool.clone()));
    let identity_repo = Arc::new(DbIdentityRepository::new(pool.clone()));

    let token_service = TokenService::new(
        refresh_token_repo.clone(),
        account_repo.clone(),
        session_repo.clone()
    );

    let auth_service = AuthService::new(account_repo.clone());
    let user_service = UserService::new(account_repo.clone(), identity_repo.clone());
    let session_service = SessionService::new(session_repo.clone());

    let token_service_data = web::Data::new(token_service);
    let auth_service_data = web::Data::new(auth_service);
    let user_service_data = web::Data::new(user_service);
    let session_service_data = web::Data::new(session_service);

    HttpServer::new(move || {
        App::new()
            .app_data(auth_service_data.clone())
            .app_data(token_service_data.clone())
            .app_data(user_service_data.clone())
            .app_data(session_service_data.clone())
            .configure(configure_routes)
            .wrap(Logger::default())
    })
    .bind(("0.0.0.0", 8403))?
    .run()
    .await
}

pub fn configure_routes(config: &mut web::ServiceConfig) {
    let scope = web::scope("/api/v1")
        .service(api::controller::signup_handler)
        .service(api::controller::token_handler)
        .service(api::controller::token_info_handler)
        .service(api::controller::signout_handler);

    config.service(scope);
}
