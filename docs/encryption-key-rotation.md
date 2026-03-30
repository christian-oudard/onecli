# Feature Request: Encryption Key Rotation and Versioned Ciphertext Envelope

## Summary

The `SECRET_ENCRYPTION_KEY` currently has no rotation support. Changing the key makes all encrypted values unrecoverable. This blocks safe key hygiene and complicates the upcoming SQLite token state store for OAuth runtime credentials.

## Problem

- Encrypted values use format `{iv}:{authTag}:{ciphertext}` with no key identifier.
- Three DB fields affected: `Secret.encryptedValue`, `AppConnection.credentials`, `AppConfig.credentials`.
- The planned SQLite token state store (for OAuth refresh tokens) will add a fourth encrypted storage location.
- No way to rotate the key without downtime and data loss.

## Proposed Design

### 1. Versioned ciphertext envelope

Replace the bare `{iv}:{authTag}:{ciphertext}` format with a self-describing envelope:

```
k:<keyId>:<iv_b64>:<authTag_b64>:<ciphertext_b64>
```

`keyId` is a truncated SHA-256 fingerprint of the key (8 hex chars). Values without the `k:` prefix are treated as legacy (decrypt with current key).

### 2. Multi-key configuration

Support a current key and retired keys (decrypt-only):

```env
SECRET_ENCRYPTION_KEY=<base64>              # current, used for all new encryptions
SECRET_ENCRYPTION_KEY_RETIRED=<base64>,...   # previous keys, decrypt-only
```

### 3. Batch migration CLI

A `onecli-gateway migrate-keys` (or web admin action) that:

- Reads every encrypted field across Postgres and SQLite.
- Decrypts with whatever key matches the `keyId`.
- Re-encrypts with the current key.
- Retired keys can be removed once migration completes.

### 4. Unified CryptoService

Both the TypeScript web app (`lib/crypto.ts`) and Rust gateway (`crypto.rs`) use the same envelope format, so one rotation covers all encrypted storage.

## Edge Cases

- **Legacy values (no prefix):** try current key, then retired keys in order.
- **Unknown keyId:** clear error log, skip that credential, don't crash.
- **Unencrypted to encrypted migration:** values without `k:` prefix are plaintext (standalone mode). When `SECRET_ENCRYPTION_KEY` is added, encrypt on next write or via batch migration.
- **Key removed after encryption:** detect `k:` prefix, log error, skip credential gracefully.

## Affected Code

- `apps/web/src/lib/crypto.ts` (TypeScript encrypt/decrypt)
- `apps/gateway/src/crypto.rs` (Rust decrypt)
- `apps/web/src/lib/services/secret-service.ts`, `connection-service.ts`, `app-config-service.ts`
- Future: `apps/gateway/src/token_state.rs` (SQLite token state store)
- `docker/entrypoint.sh` (key generation)
- No Prisma schema change needed. The envelope is in the value itself.

## Context

This came up while designing the OAuth runtime token state store for the standalone gateway split. The SQLite store needs encryption when `SECRET_ENCRYPTION_KEY` is available. Both storage backends (Postgres and SQLite) should use the same envelope format from the start to avoid a second migration later.
