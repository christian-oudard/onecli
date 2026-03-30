import { db, Prisma } from "@onecli/db";
import { ServiceError } from "@/lib/services/errors";
import {
  putTokenState,
  deleteTokenState,
} from "@/lib/services/token-state-service";

/**
 * List all app connections for an account (no credentials returned).
 */
export const listConnections = async (accountId: string) => {
  return db.appConnection.findMany({
    where: { accountId },
    select: {
      id: true,
      provider: true,
      status: true,
      scopes: true,
      metadata: true,
      connectedAt: true,
    },
    orderBy: { connectedAt: "desc" },
  });
};

/**
 * Create or update an app connection.
 *
 * If the credentials include a refresh_token (OAuth providers with token
 * refresh, e.g. Google), tokens are written to the gateway's SQLite token
 * state store. Providers without refresh tokens (e.g. GitHub) store
 * the access_token only. Postgres stores non-secret metadata.
 */
export const upsertConnection = async (
  accountId: string,
  provider: string,
  credentials: Record<string, unknown>,
  options?: { scopes?: string[]; metadata?: Record<string, unknown> },
) => {
  // Write tokens to the gateway's SQLite (encrypted) if present.
  const accessToken = credentials.access_token as string | undefined;
  const refreshToken = credentials.refresh_token as string | undefined;
  const expiresAt = credentials.expires_at as number | undefined;

  if (accessToken) {
    await putTokenState(
      provider,
      accountId,
      accessToken,
      refreshToken ?? "",
      expiresAt ?? null,
    );
  }

  // Postgres stores connection metadata only (no tokens).
  return db.appConnection.upsert({
    where: { accountId_provider: { accountId, provider } },
    create: {
      accountId,
      provider,
      status: "connected",
      scopes: options?.scopes ?? [],
      metadata: (options?.metadata as Prisma.InputJsonValue) ?? undefined,
    },
    update: {
      status: "connected",
      scopes: options?.scopes ?? undefined,
      metadata: (options?.metadata as Prisma.InputJsonValue) ?? undefined,
    },
    select: { id: true, provider: true, status: true },
  });
};

/**
 * Delete an app connection.
 */
export const deleteConnection = async (accountId: string, provider: string) => {
  const connection = await db.appConnection.findUnique({
    where: { accountId_provider: { accountId, provider } },
    select: { id: true },
  });

  if (!connection) {
    throw new ServiceError("NOT_FOUND", "Connection not found");
  }

  // Remove tokens from gateway's SQLite.
  deleteTokenState(provider, accountId);

  await db.appConnection.delete({
    where: { accountId_provider: { accountId, provider } },
  });
};
