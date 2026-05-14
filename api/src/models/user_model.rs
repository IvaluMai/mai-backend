use mysql::{params, prelude::*};
use actix_web::http::StatusCode;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::{rand_core::OsRng, SaltString}};
use derive_more::{Display, Error, From};
use serde::Deserialize;

#[derive(Debug, Display, Error, From)]
pub enum PersistenceError {
    UsernameAlreadyTaken,
    EmailAlreadyTaken,

    WrongCredentials,

    MysqlError(mysql::Error),

    Unknown,
}

impl actix_web::ResponseError for PersistenceError {
    fn status_code(&self) -> StatusCode {
        match self {
            PersistenceError::UsernameAlreadyTaken
            | PersistenceError::EmailAlreadyTaken => StatusCode::CONFLICT,

            PersistenceError::WrongCredentials => StatusCode::UNAUTHORIZED,

            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> actix_web::HttpResponse {
        let message = match self {
            PersistenceError::UsernameAlreadyTaken => "This username is already taken",
            PersistenceError::EmailAlreadyTaken => "This email is already in use",
            PersistenceError::WrongCredentials => "Invalid username or password",
            _ => "An unexpected error occurred",
        };
        actix_web::HttpResponse::build(self.status_code()).body(message)
    }
}

pub(crate) fn register(
    pool: &mysql::Pool,
    register_data: RegisterData,
) -> Result<(), PersistenceError> {
    let mut conn = pool.get_conn()?;

    if check_username_exists(&mut conn, register_data.username.clone()) {
        return Err(PersistenceError::UsernameAlreadyTaken);
    }

    if check_email_exists(&mut conn, register_data.email.clone()) {
        return Err(PersistenceError::EmailAlreadyTaken);
    }

    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(register_data.password.as_bytes(), &salt)
        .map_err(|_| PersistenceError::Unknown)?
        .to_string();

    let user_id = insert_user(
        &mut conn,
        register_data.username,
        hashed_password,
        register_data.email,
        register_data.birthdate,
        register_data.firstname,
        register_data.lastname,
    )?;

    if user_id > 0 {
        Ok(())
    } else {
        Err(PersistenceError::Unknown)
    }
}

/// Verifies credentials and returns the user's id on success.
pub(crate) fn login(
    pool: &mysql::Pool,
    login_data: LoginData,
) -> Result<u64, PersistenceError> {
    let mut conn = pool.get_conn()?;

    let user_id = get_user_id_by_username(&mut conn, login_data.username.clone())?;

    let stored_hash = get_password_by_user_id(&mut conn, user_id)?;
    let parsed_hash = PasswordHash::new(&stored_hash)
        .map_err(|_| PersistenceError::Unknown)?;
    Argon2::default()
        .verify_password(login_data.password.as_bytes(), &parsed_hash)
        .map_err(|_| PersistenceError::WrongCredentials)?;

    Ok(user_id)
}

// users table related
#[derive(Debug, Deserialize)]
pub struct RegisterData {
    pub username:   String,
    pub password:   String,
    pub email:      String,
    pub birthdate:  String,
    pub firstname:  String,
    pub lastname:   String,
}

fn insert_user(
    conn: &mut mysql::PooledConn,
    username:   String,
    password:   String,
    email:      String,
    birthdate:  String,
    firstname:  String,
    lastname:   String,
) -> mysql::error::Result<u64> {
    conn.exec_drop(
        "INSERT INTO users (username, password, email, birthdate, first_name, last_name)
        VALUES (:username, :password, :email, :birthdate, :first_name, :last_name)",
        params! {
            "username"   => username,
            "password"   => password,
            "email"      => email,
            "birthdate"  => birthdate,
            "first_name" => firstname,
            "last_name"  => lastname,
        },
    ).map(|_| conn.last_insert_id())
}

fn get_password_by_user_id(
    conn: &mut mysql::PooledConn,
    user_id: u64,
) -> mysql::error::Result<String> {
    conn.exec_first(
        "SELECT password FROM users WHERE id = :user_id",
        params! {
            "user_id" => user_id,
        }
    ).map(Option::unwrap)
}

fn get_user_id_by_username(
    conn: &mut mysql::PooledConn,
    username: String,
) -> mysql::error::Result<u64> {
    conn.exec_first(
        "SELECT id FROM users WHERE username = :username",
        params! {
            "username" => username,
        }
    ).map(Option::unwrap)
}

fn check_username_exists(
    conn: &mut mysql::PooledConn,
    username: String,
) -> bool {
    conn.exec_first(
        "SELECT EXISTS(SELECT username FROM users WHERE username = :username)",
        params! {
            "username" => username,
        },
    ).map(|result: Option<(u8,)>| result.map_or(false, |(exists,)| exists == 1))
        .unwrap_or(false)
}

fn check_email_exists(
    conn: &mut mysql::PooledConn,
    email: String,
) -> bool {
    conn.exec_first(
        "SELECT EXISTS(SELECT email FROM users WHERE email = :email)",
        params! {
            "email" => email,
        },
    ).map(|result: Option<(u8,)>| result.map_or(false, |(exists,)| exists == 1))
        .unwrap_or(false)
}

// Login related
#[derive(Debug, Deserialize)]
pub struct LoginData {
    pub username: String,
    pub password: String,
}
