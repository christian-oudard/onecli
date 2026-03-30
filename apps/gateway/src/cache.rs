//! In-memory cache for rate limiting.
//!
//! Provides `del_by_prefix` (clear counters on rule reload) and
//! `incr` (atomic counter with TTL for rate limit windows).

use std::time::{Duration, Instant};

use async_trait::async_trait;
use dashmap::DashMap;

/// Rate-limit cache store.
#[async_trait]
pub(crate) trait CacheStore: Send + Sync {
    /// Delete all keys matching a prefix.
    async fn del_by_prefix(&self, prefix: &str);

    /// Atomically increment a counter at `key`.
    /// Sets TTL only on first increment (new key / expired key).
    /// Returns the new count, or `None` on error (graceful fallback).
    async fn incr(&self, key: &str, ttl_secs: u64) -> Option<u64>;
}

/// Create the cache store for this build.
/// OSS: in-memory DashMap. Cloud: Redis (swapped via `#[cfg]`).
pub(crate) async fn create_store() -> anyhow::Result<std::sync::Arc<dyn CacheStore>> {
    Ok(std::sync::Arc::new(InMemoryCacheStore::new()))
}

// ── In-memory implementation ─────────────────────────────────────────────

struct CachedEntry {
    data: String,
    expires_at: Instant,
}

/// In-memory cache backed by `DashMap`. Used in OSS (single-instance).
///
/// Expired entries are evicted lazily on read — no background reaper.
/// Acceptable for the gateway's bounded key space (one entry per
/// agent×host pair), but not suitable for unbounded key sets.
struct InMemoryCacheStore {
    map: DashMap<String, CachedEntry>,
}

impl InMemoryCacheStore {
    pub fn new() -> Self {
        Self {
            map: DashMap::new(),
        }
    }
}

#[async_trait]
impl CacheStore for InMemoryCacheStore {
    async fn del_by_prefix(&self, prefix: &str) {
        self.map.retain(|key, _| !key.starts_with(prefix));
    }

    async fn incr(&self, key: &str, ttl_secs: u64) -> Option<u64> {
        let now = Instant::now();
        let ttl = Duration::from_secs(ttl_secs);

        let mut entry = self.map.entry(key.to_string()).or_insert(CachedEntry {
            data: "0".to_string(),
            expires_at: now + ttl,
        });

        // Reset if expired
        if entry.expires_at <= now {
            entry.data = "0".to_string();
            entry.expires_at = now + ttl;
        }

        let count: u64 = entry.data.parse().unwrap_or(0) + 1;
        entry.data = count.to_string();
        Some(count)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn new_store() -> Arc<dyn CacheStore> {
        Arc::new(InMemoryCacheStore::new())
    }

    #[tokio::test]
    async fn del_by_prefix_removes_matching_entries() {
        let store = new_store();

        // Seed some entries via incr
        store.incr("connect:acc1:tok1:host1", 60).await;
        store.incr("connect:acc1:tok2:host2", 60).await;
        store.incr("connect:acc2:tok3:host3", 60).await;
        store.incr("rate:rule1:tok1:123", 60).await;

        store.del_by_prefix("connect:acc1:").await;

        // Deleted entries return count=1 (fresh) on next incr
        assert_eq!(
            store.incr("connect:acc1:tok1:host1", 60).await,
            Some(1),
            "should be fresh after delete"
        );
        // Surviving entries return count=2 (already had 1)
        assert_eq!(
            store.incr("connect:acc2:tok3:host3", 60).await,
            Some(2),
            "should still have prior count"
        );
        assert_eq!(
            store.incr("rate:rule1:tok1:123", 60).await,
            Some(2),
            "non-matching prefix should survive"
        );
    }
}
