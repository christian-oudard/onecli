//! Direct database access via SQLx.
//!
//! The gateway uses the database only for browser auth (user/account lookup) and
//! vault connection state. Rules and secrets are delivered via the in-memory watch
//! channel — either loaded from the JSON config file or pushed by the web UI over
//! the control socket.

use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
use sqlx::{FromRow, PgPool};

/// Create a PostgreSQL connection pool from a connection URL.
pub(crate) async fn create_pool(database_url: &str) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
        .context("connecting to PostgreSQL")
}

/// A user row from the `users` table.
#[derive(Debug, FromRow)]
pub(crate) struct UserRow {
    pub id: String,
}

/// An API key row from the `api_keys` table.
#[derive(Debug, FromRow)]
pub(crate) struct ApiKeyRow {
    pub user_id: String,
    pub account_id: String,
}

/// A vault connection row from the `vault_connections` table.
#[derive(Debug, FromRow)]
#[allow(dead_code)]
pub(crate) struct VaultConnectionRow {
    pub id: String,
    pub provider: String,
    pub name: Option<String>,
    pub status: String,
    pub connection_data: Option<serde_json::Value>,
}

// ── Queries ─────────────────────────────────────────────────────────────

/// Look up a user by their external auth ID (e.g. OAuth `sub` claim or "local-admin").
pub(crate) async fn find_user_by_external_auth_id(
    pool: &PgPool,
    external_auth_id: &str,
) -> Result<Option<UserRow>> {
    sqlx::query_as::<_, UserRow>(r#"SELECT id FROM users WHERE external_auth_id = $1 LIMIT 1"#)
        .bind(external_auth_id)
        .fetch_optional(pool)
        .await
        .context("querying user by external_auth_id")
}

/// Find the account ID for a user (from account_members table).
pub(crate) async fn find_account_id_by_user(
    pool: &PgPool,
    user_id: &str,
) -> Result<Option<String>> {
    let row: Option<(String,)> =
        sqlx::query_as(r#"SELECT account_id FROM account_members WHERE user_id = $1 LIMIT 1"#)
            .bind(user_id)
            .fetch_optional(pool)
            .await
            .context("querying account_members by user_id")?;

    Ok(row.map(|(id,)| id))
}

/// Look up an API key (`oc_...`) and return its user_id and account_id.
pub(crate) async fn find_api_key(pool: &PgPool, key: &str) -> Result<Option<ApiKeyRow>> {
    sqlx::query_as::<_, ApiKeyRow>(
        r#"SELECT user_id, account_id FROM api_keys WHERE key = $1 LIMIT 1"#,
    )
    .bind(key)
    .fetch_optional(pool)
    .await
    .context("querying api_keys by key")
}

// ── Vault connection queries ────────────────────────────────────────────

/// Find a vault connection for an account + provider pair.
pub(crate) async fn find_vault_connection(
    pool: &PgPool,
    account_id: &str,
    provider: &str,
) -> Result<Option<VaultConnectionRow>> {
    sqlx::query_as::<_, VaultConnectionRow>(
        r#"SELECT id, provider, name, status, connection_data FROM vault_connections WHERE account_id = $1 AND provider = $2 LIMIT 1"#,
    )
    .bind(account_id)
    .bind(provider)
    .fetch_optional(pool)
    .await
    .context("querying vault_connection by account_id + provider")
}

/// Upsert a vault connection (insert or update on account_id + provider conflict).
pub(crate) async fn upsert_vault_connection(
    pool: &PgPool,
    account_id: &str,
    provider: &str,
    status: &str,
    connection_data: Option<&serde_json::Value>,
) -> Result<()> {
    sqlx::query(
        r#"INSERT INTO vault_connections (id, account_id, provider, status, connection_data, created_at, updated_at)
           VALUES (gen_random_uuid()::text, $1, $2, $3, $4, NOW(), NOW())
           ON CONFLICT (account_id, provider)
           DO UPDATE SET status = $3, connection_data = $4, updated_at = NOW()"#,
    )
    .bind(account_id)
    .bind(provider)
    .bind(status)
    .bind(connection_data)
    .execute(pool)
    .await
    .context("upserting vault_connection")?;
    Ok(())
}

/// Update only the connection_data JSON for an existing vault connection.
pub(crate) async fn update_vault_connection_data(
    pool: &PgPool,
    account_id: &str,
    provider: &str,
    connection_data: &serde_json::Value,
) -> Result<()> {
    sqlx::query(
        r#"UPDATE vault_connections SET connection_data = $3, updated_at = NOW() WHERE account_id = $1 AND provider = $2"#,
    )
    .bind(account_id)
    .bind(provider)
    .bind(connection_data)
    .execute(pool)
    .await
    .context("updating vault_connection connection_data")?;
    Ok(())
}

/// Delete a vault connection for an account + provider pair.
pub(crate) async fn delete_vault_connection(
    pool: &PgPool,
    account_id: &str,
    provider: &str,
) -> Result<()> {
    sqlx::query(r#"DELETE FROM vault_connections WHERE account_id = $1 AND provider = $2"#)
        .bind(account_id)
        .bind(provider)
        .execute(pool)
        .await
        .context("deleting vault_connection")?;
    Ok(())
}
