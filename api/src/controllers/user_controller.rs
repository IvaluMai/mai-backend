use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;

#[path = "../models/user_model.rs"] mod user_model;

#[derive(Deserialize)]
struct RegisterRequest {
    user: user_model::RegisterData,
}

#[derive(Deserialize)]
struct LoginRequest {
    user: user_model::LoginData,
}

#[derive(Deserialize)]
struct LogoutRequest {
    user: user_model::LogoutData,
}

pub fn user_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/user")
            .route("/register",     web::to(register))
            .route("/login",    web::to(login))
            .route("/logout",   web::to(logout)),
    );
}


async fn register(
    data: web::Data<mysql::Pool>,
    web::Json(RegisterRequest { user: register_data }): web::Json<RegisterRequest>,
) -> actix_web::Result<impl Responder> {

    web::block(move || user_model::register(&data, register_data)).await??;

    Ok(HttpResponse::Created().body("User registered successfully"))
}

async fn login(
    data: web::Data<mysql::Pool>,
    web::Json(LoginRequest { user: login_data }): web::Json<LoginRequest>,
) -> actix_web::Result<impl Responder> {

    let session_token = web::block(move || user_model::login(&data, login_data)).await??;

    Ok(HttpResponse::Ok().body(session_token))
}

async fn logout(
    data: web::Data<mysql::Pool>,
    web::Json(LogoutRequest { user: logout_data }): web::Json<LogoutRequest>,
) -> actix_web::Result<impl Responder> {

    web::block(move || user_model::logout(&data, logout_data)).await??;

    Ok(HttpResponse::Ok().body("User logged out successfully"))
}