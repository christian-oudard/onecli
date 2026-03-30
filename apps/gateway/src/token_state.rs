//! SQLite-backed runtime token state store.
//!
//! Stores OAuth access and refresh tokens for app connections. Used by both
//! web UI mode (tokens pushed via control socket) and standalone mode.
//! All credential values are encrypted with the `SECRET_ENCRYPTION_KEY`
//! using the same AES-256-GCM format as the Node.js CryptoService.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::Mutex;

use crate::crypto::CryptoService;

// ── Types ──────────────────────────────────────────────────────────────

/// Runtime OAuth token state for a single app connection.
#[derive(Debug, Clone)]
pub(crate) struct TokenState {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: Option<i64>,
}

impl TokenState {
    /// Returns true if the access token is expired or will expire within 60 seconds.
    pub fn is_expired(&self) -> bool {
        let Some(expires_at) = self.expires_at else {
            return false;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs() as i64;
        now >= expires_at - 60
    }
}

// ── Store ──────────────────────────────────────────────────────────────

/// Encrypted SQLite store for OAuth runtime token state.
///
/// Thread-safe: uses connection pooling via sqlx and per-key mutexes
/// for single-flight token refresh.
pub(crate) struct TokenStateStore {
    pool: sqlx::SqlitePool,
    crypto: CryptoService,
    /// Per-key mutexes for single-flight refresh operations.
    refresh_locks: dashmap::DashMap<String, Arc<Mutex<()>>>,
}

impl TokenStateStore {
    /// Open (or create) the token state database at `data_dir/token_state.db`.
    pub async fn open(data_dir: &Path, crypto: CryptoService) -> Result<Self> {
        let db_path = data_dir.join("token_state.db");
        let url = format!("sqlite:{}?mode=rwc", db_path.display());

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .with_context(|| format!("opening SQLite database at {}", db_path.display()))?;

        // Enable WAL mode for concurrent readers.
        sqlx::query("PRAGMA journal_mode=WAL")
            .execute(&pool)
            .await
            .context("setting SQLite WAL mode")?;

        // Create table if it doesn't exist.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS token_state (
                provider     TEXT NOT NULL,
                account_id   TEXT NOT NULL,
                access_token TEXT NOT NULL,
                refresh_token TEXT NOT NULL,
                expires_at   INTEGER,
                updated_at   INTEGER NOT NULL,
                PRIMARY KEY (provider, account_id)
            )",
        )
        .execute(&pool)
        .await
        .context("creating token_state table")?;

        Ok(Self {
            pool,
            crypto,
            refresh_locks: dashmap::DashMap::new(),
        })
    }

    /// Get the token state for a provider + account pair.
    pub async fn get(&self, provider: &str, account_id: &str) -> Result<Option<TokenState>> {
        let row: Option<(String, String, Option<i64>)> = sqlx::query_as(
            "SELECT access_token, refresh_token, expires_at FROM token_state WHERE provider = ?1 AND account_id = ?2",
        )
        .bind(provider)
        .bind(account_id)
        .fetch_optional(&self.pool)
        .await
        .context("querying token_state")?;

        let Some((enc_access, enc_refresh, expires_at)) = row else {
            return Ok(None);
        };

        let access_token = self
            .crypto
            .decrypt(&enc_access)
            .await
            .context("decrypting access_token")?;
        let refresh_token = self
            .crypto
            .decrypt(&enc_refresh)
            .await
            .context("decrypting refresh_token")?;

        Ok(Some(TokenState {
            access_token,
            refresh_token,
            expires_at,
        }))
    }

    /// Store (upsert) token state for a provider + account pair.
    pub async fn put(&self, provider: &str, account_id: &str, state: &TokenState) -> Result<()> {
        let enc_access = self
            .crypto
            .encrypt(&state.access_token)
            .context("encrypting access_token")?;
        let enc_refresh = self
            .crypto
            .encrypt(&state.refresh_token)
            .context("encrypting refresh_token")?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs() as i64;

        sqlx::query(
            "INSERT INTO token_state (provider, account_id, access_token, refresh_token, expires_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (provider, account_id)
             DO UPDATE SET access_token = ?3, refresh_token = ?4, expires_at = ?5, updated_at = ?6",
        )
        .bind(provider)
        .bind(account_id)
        .bind(&enc_access)
        .bind(&enc_refresh)
        .bind(state.expires_at)
        .bind(now)
        .execute(&self.pool)
        .await
        .context("upserting token_state")?;

        Ok(())
    }

    /// Delete token state for a provider + account pair.
    #[allow(dead_code)]
    pub async fn delete(&self, provider: &str, account_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM token_state WHERE provider = ?1 AND account_id = ?2")
            .bind(provider)
            .bind(account_id)
            .execute(&self.pool)
            .await
            .context("deleting token_state")?;

        Ok(())
    }

    /// Get or create a mutex for single-flight refresh of a specific key.
    pub(crate) fn refresh_lock(&self, provider: &str, account_id: &str) -> Arc<Mutex<()>> {
        let key = format!("{provider}:{account_id}");
        self.refresh_locks
            .entry(key)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_crypto() -> CryptoService {
        use base64::Engine;
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut key = [0u8; 32];
        rng.fill(&mut key).unwrap();
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
        CryptoService::from_base64_key(&key_b64).unwrap()
    }

    async fn temp_store() -> (TokenStateStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = TokenStateStore::open(dir.path(), test_crypto())
            .await
            .unwrap();
        (store, dir)
    }

    #[tokio::test]
    async fn get_missing_returns_none() {
        let (store, _dir) = temp_store().await;
        assert!(store.get("github", "acc1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn put_and_get_round_trip() {
        let (store, _dir) = temp_store().await;
        let state = TokenState {
            access_token: "gho_access123".to_string(),
            refresh_token: "ghr_refresh456".to_string(),
            expires_at: Some(1711900000),
        };
        store.put("github", "acc1", &state).await.unwrap();

        let got = store.get("github", "acc1").await.unwrap().unwrap();
        assert_eq!(got.access_token, "gho_access123");
        assert_eq!(got.refresh_token, "ghr_refresh456");
        assert_eq!(got.expires_at, Some(1711900000));
    }

    #[tokio::test]
    async fn put_upserts_existing() {
        let (store, _dir) = temp_store().await;
        let state1 = TokenState {
            access_token: "old".to_string(),
            refresh_token: "old_refresh".to_string(),
            expires_at: Some(100),
        };
        store.put("github", "acc1", &state1).await.unwrap();

        let state2 = TokenState {
            access_token: "new".to_string(),
            refresh_token: "new_refresh".to_string(),
            expires_at: Some(200),
        };
        store.put("github", "acc1", &state2).await.unwrap();

        let got = store.get("github", "acc1").await.unwrap().unwrap();
        assert_eq!(got.access_token, "new");
        assert_eq!(got.refresh_token, "new_refresh");
        assert_eq!(got.expires_at, Some(200));
    }

    #[tokio::test]
    async fn delete_removes_entry() {
        let (store, _dir) = temp_store().await;
        let state = TokenState {
            access_token: "a".to_string(),
            refresh_token: "r".to_string(),
            expires_at: None,
        };
        store.put("github", "acc1", &state).await.unwrap();
        store.delete("github", "acc1").await.unwrap();
        assert!(store.get("github", "acc1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn different_providers_are_independent() {
        let (store, _dir) = temp_store().await;
        let gh = TokenState {
            access_token: "gh_tok".to_string(),
            refresh_token: "gh_ref".to_string(),
            expires_at: None,
        };
        let google = TokenState {
            access_token: "google_tok".to_string(),
            refresh_token: "google_ref".to_string(),
            expires_at: Some(999),
        };
        store.put("github", "acc1", &gh).await.unwrap();
        store.put("google", "acc1", &google).await.unwrap();

        let got_gh = store.get("github", "acc1").await.unwrap().unwrap();
        assert_eq!(got_gh.access_token, "gh_tok");

        let got_google = store.get("google", "acc1").await.unwrap().unwrap();
        assert_eq!(got_google.access_token, "google_tok");
    }

    #[tokio::test]
    async fn values_are_encrypted_at_rest() {
        let (store, _dir) = temp_store().await;
        let state = TokenState {
            access_token: "plaintext_token".to_string(),
            refresh_token: "plaintext_refresh".to_string(),
            expires_at: None,
        };
        store.put("github", "acc1", &state).await.unwrap();

        // Read raw values from SQLite - they should NOT be plaintext
        let row: (String, String) = sqlx::query_as(
            "SELECT access_token, refresh_token FROM token_state WHERE provider = ?1 AND account_id = ?2",
        )
        .bind("github")
        .bind("acc1")
        .fetch_one(&store.pool)
        .await
        .unwrap();

        assert_ne!(row.0, "plaintext_token");
        assert_ne!(row.1, "plaintext_refresh");
        // Encrypted values contain colons (iv:tag:ciphertext format)
        assert!(row.0.contains(':'));
        assert!(row.1.contains(':'));
    }

    #[test]
    fn is_expired_with_no_expiry() {
        let state = TokenState {
            access_token: "a".to_string(),
            refresh_token: "r".to_string(),
            expires_at: None,
        };
        assert!(!state.is_expired());
    }

    #[test]
    fn is_expired_with_past_expiry() {
        let state = TokenState {
            access_token: "a".to_string(),
            refresh_token: "r".to_string(),
            expires_at: Some(0),
        };
        assert!(state.is_expired());
    }

    #[test]
    fn is_expired_with_future_expiry() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let state = TokenState {
            access_token: "a".to_string(),
            refresh_token: "r".to_string(),
            expires_at: Some(now + 3600),
        };
        assert!(!state.is_expired());
    }

    #[test]
    fn is_expired_within_60s_buffer() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        // Expires in 30 seconds - within the 60s buffer
        let state = TokenState {
            access_token: "a".to_string(),
            refresh_token: "r".to_string(),
            expires_at: Some(now + 30),
        };
        assert!(state.is_expired());
    }
}
