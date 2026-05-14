use actix_session::Session;
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

pub fn public_user_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/user")
            .route("/register", web::to(register))
            .route("/login",    web::to(login)),
    );
}

pub fn protected_user_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/user")
            .route("/logout", web::to(logout)),
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
    session: Session,
    web::Json(LoginRequest { user: login_data }): web::Json<LoginRequest>,
) -> actix_web::Result<impl Responder> {

    let user_id = web::block(move || user_model::login(&data, login_data)).await??;

    session.insert("user_id", user_id)
        .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().finish())
}

async fn logout(session: Session) -> impl Responder {
    session.purge();
    HttpResponse::Ok().finish()
}
