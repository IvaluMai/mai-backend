use std::collections::HashMap;

use actix_session::storage::{LoadError, SaveError, SessionKey, SessionStore, UpdateError};
use actix_web::cookie::{time::Duration, Key};
use mysql::{params, prelude::*};
use tokio::task;

#[derive(Clone)]
pub struct MySqlSessionStore {
    pool: mysql::Pool,
}

impl MySqlSessionStore {
    pub fn new(pool: mysql::Pool) -> Self {
        Self { pool }
    }

    fn generate_token() -> String {
        Key::generate()
            .master()[..32]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

impl SessionStore for MySqlSessionStore {
    async fn load(
        &self,
        session_key: &SessionKey,
    ) -> Result<Option<HashMap<String, String>>, LoadError> {
        let pool = self.pool.clone();
        let key = session_key.as_ref().to_owned();

        task::spawn_blocking(move || {
            let mut conn = pool
                .get_conn()
                .map_err(|e| LoadError::Other(anyhow::anyhow!("{e}")))?;
            let now = chrono::Utc::now()
                .format("%Y-%m-%d %H:%M:%S")
                .to_string();

            let result: Option<String> = conn
                .exec_first(
                    "SELECT session_data FROM user_sessions \
                     WHERE session_token = :token AND expires_at > :now",
                    params! { "token" => &key, "now" => &now },
                )
                .map_err(|e| LoadError::Other(anyhow::anyhow!("{e}")))?;

            match result {
                Some(data) => {
                    let state = serde_json::from_str(&data)
                        .map_err(|e| LoadError::Deserialization(anyhow::anyhow!("{e}")))?;
                    Ok(Some(state))
                }
                None => Ok(None),
            }
        })
        .await
        .map_err(|e| LoadError::Other(anyhow::anyhow!("{e}")))?
    }

    async fn save(
        &self,
        session_state: HashMap<String, String>,
        ttl: &Duration,
    ) -> Result<SessionKey, SaveError> {
        let pool = self.pool.clone();
        let data = serde_json::to_string(&session_state)
            .map_err(|e| SaveError::Serialization(anyhow::anyhow!("{e}")))?;
        let expires_at = (chrono::Utc::now()
            + chrono::Duration::seconds(ttl.whole_seconds()))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

        task::spawn_blocking(move || {
            let mut conn = pool
                .get_conn()
                .map_err(|e| SaveError::Other(anyhow::anyhow!("{e}")))?;

            let token = loop {
                let candidate = MySqlSessionStore::generate_token();
                let exists: Option<u8> = conn
                    .exec_first(
                        "SELECT 1 FROM user_sessions WHERE session_token = :token",
                        params! { "token" => &candidate },
                    )
                    .map_err(|e| SaveError::Other(anyhow::anyhow!("{e}")))?;
                if exists.is_none() {
                    break candidate;
                }
            };

            conn.exec_drop(
                "INSERT INTO user_sessions (session_token, session_data, expires_at) \
                 VALUES (:token, :data, :expires_at)",
                params! {
                    "token"      => &token,
                    "data"       => &data,
                    "expires_at" => &expires_at,
                },
            )
            .map_err(|e| SaveError::Other(anyhow::anyhow!("{e}")))?;

            SessionKey::try_from(token)
                .map_err(|e| SaveError::Other(anyhow::anyhow!("{e}")))
        })
        .await
        .map_err(|e| SaveError::Other(anyhow::anyhow!("{e}")))?
    }

    async fn update(
        &self,
        session_key: SessionKey,
        session_state: HashMap<String, String>,
        ttl: &Duration,
    ) -> Result<SessionKey, UpdateError> {
        let pool = self.pool.clone();
        let key = session_key.as_ref().to_owned();
        let data = serde_json::to_string(&session_state)
            .map_err(|e| UpdateError::Serialization(anyhow::anyhow!("{e}")))?;
        let expires_at = (chrono::Utc::now()
            + chrono::Duration::seconds(ttl.whole_seconds()))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

        task::spawn_blocking(move || {
            let mut conn = pool
                .get_conn()
                .map_err(|e| UpdateError::Other(anyhow::anyhow!("{e}")))?;

            conn.exec_drop(
                "UPDATE user_sessions \
                 SET session_data = :data, expires_at = :expires_at \
                 WHERE session_token = :token",
                params! {
                    "data"       => &data,
                    "expires_at" => &expires_at,
                    "token"      => &key,
                },
            )
            .map_err(|e| UpdateError::Other(anyhow::anyhow!("{e}")))?;

            SessionKey::try_from(key)
                .map_err(|e| UpdateError::Other(anyhow::anyhow!("{e}")))
        })
        .await
        .map_err(|e| UpdateError::Other(anyhow::anyhow!("{e}")))?
    }

    async fn update_ttl(
        &self,
        session_key: &SessionKey,
        ttl: &Duration,
    ) -> Result<(), anyhow::Error> {
        let pool = self.pool.clone();
        let key = session_key.as_ref().to_owned();
        let expires_at = (chrono::Utc::now()
            + chrono::Duration::seconds(ttl.whole_seconds()))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

        task::spawn_blocking(move || -> Result<(), anyhow::Error> {
            let mut conn = pool.get_conn().map_err(|e| anyhow::anyhow!("{e}"))?;
            conn.exec_drop(
                "UPDATE user_sessions SET expires_at = :expires_at \
                 WHERE session_token = :token",
                params! { "expires_at" => &expires_at, "token" => &key },
            )
            .map_err(|e| anyhow::anyhow!("{e}"))
        })
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
    }

    async fn delete(&self, session_key: &SessionKey) -> Result<(), anyhow::Error> {
        let pool = self.pool.clone();
        let key = session_key.as_ref().to_owned();

        task::spawn_blocking(move || -> Result<(), anyhow::Error> {
            let mut conn = pool.get_conn().map_err(|e| anyhow::anyhow!("{e}"))?;
            conn.exec_drop(
                "DELETE FROM user_sessions WHERE session_token = :token",
                params! { "token" => &key },
            )
            .map_err(|e| anyhow::anyhow!("{e}"))
        })
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
    }
}
