/**
 * Token state service: writes OAuth runtime credentials to the gateway's
 * SQLite database at `{GATEWAY_DATA_DIR}/token_state.db`.
 *
 * The web UI and gateway share this database file. The web UI writes tokens
 * after OAuth authorization, and the gateway reads them at CONNECT time
 * for credential injection.
 *
 * Requires `better-sqlite3` (`pnpm add better-sqlite3 @types/better-sqlite3`).
 */

import Database from "better-sqlite3";
import path from "path";
import { cryptoService } from "@/lib/crypto";
import { logger } from "@/lib/logger";

// ── Database path ────────────────────────────────────────────────────────

const gatewayDataDir = (): string =>
  process.env.GATEWAY_DATA_DIR ?? "/app/data";

let db: Database.Database | null = null;

const getDb = (): Database.Database => {
  if (db) return db;

  const dbPath = path.join(gatewayDataDir(), "token_state.db");
  db = new Database(dbPath);
  db.pragma("journal_mode = WAL");

  // Create table if the gateway hasn't started yet.
  db.exec(`
    CREATE TABLE IF NOT EXISTS token_state (
      provider      TEXT NOT NULL,
      account_id    TEXT NOT NULL,
      access_token  TEXT NOT NULL,
      refresh_token TEXT NOT NULL,
      expires_at    INTEGER,
      updated_at    INTEGER NOT NULL,
      PRIMARY KEY (provider, account_id)
    )
  `);

  return db;
};

// ── Public API ───────────────────────────────────────────────────────────

/**
 * Store OAuth tokens for a provider + account pair.
 * Values are encrypted with SECRET_ENCRYPTION_KEY before writing.
 */
export const putTokenState = async (
  provider: string,
  accountId: string,
  accessToken: string,
  refreshToken: string,
  expiresAt: number | null,
): Promise<void> => {
  const encAccess = await cryptoService.encrypt(accessToken);
  const encRefresh = await cryptoService.encrypt(refreshToken);
  const now = Math.floor(Date.now() / 1000);

  try {
    const stmt = getDb().prepare(`
      INSERT INTO token_state (provider, account_id, access_token, refresh_token, expires_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT (provider, account_id)
      DO UPDATE SET access_token = ?, refresh_token = ?, expires_at = ?, updated_at = ?
    `);
    stmt.run(
      provider,
      accountId,
      encAccess,
      encRefresh,
      expiresAt,
      now,
      encAccess,
      encRefresh,
      expiresAt,
      now,
    );
  } catch (err) {
    logger.error({ provider, accountId, err }, "failed to write token state");
    throw err;
  }
};

/**
 * Delete token state for a provider + account pair.
 */
export const deleteTokenState = (provider: string, accountId: string): void => {
  try {
    const stmt = getDb().prepare(
      "DELETE FROM token_state WHERE provider = ? AND account_id = ?",
    );
    stmt.run(provider, accountId);
  } catch (err) {
    logger.error({ provider, accountId, err }, "failed to delete token state");
  }
};
