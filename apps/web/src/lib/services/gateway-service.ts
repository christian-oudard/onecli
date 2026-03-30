/**
 * Gateway push service.
 *
 * Builds a full RulesSnapshot from the database (decrypting secrets) and
 * pushes it to the gateway over the Unix domain control socket. Called after
 * every database mutation that affects rules (agents, secrets, policy rules).
 *
 * If the socket does not exist (gateway not running), logs a warning and
 * returns silently. The database is the source of truth; the gateway
 * starts with empty rules and picks up state on the next push.
 */

import http from "http";
import path from "path";
import { db } from "@onecli/db";
import { cryptoService } from "@/lib/crypto";
import { logger } from "@/lib/logger";

// ── Types matching the Rust RulesSnapshot wire format ────────────────────

type SetHeaderInjection = { action: "set_header"; name: string; value: string };
type ReplaceHeaderInjection = {
  action: "replace_header";
  name: string;
  value: string;
};
type RemoveHeaderInjection = { action: "remove_header"; name: string };
type Injection =
  | SetHeaderInjection
  | ReplaceHeaderInjection
  | RemoveHeaderInjection;

type InjectionRuleConfig = {
  path_pattern: string;
  injections: Injection[];
};

type HostRule = {
  host_pattern: string;
  injection_rules: InjectionRuleConfig[];
};

type PolicyRuleConfig = {
  rule_id: string;
  host_pattern: string;
  path_pattern: string | null;
  method: string | null;
  action: string;
  rate_limit: number | null;
  rate_limit_window: string | null;
};

type AppConnectionConfig = {
  provider: string;
};

type AgentRules = {
  token: string;
  account_id: string;
  host_rules: HostRule[];
  policy_rules: PolicyRuleConfig[];
  app_connections: AppConnectionConfig[];
};

type RulesSnapshot = {
  agents: AgentRules[];
};

// ── Socket path ──────────────────────────────────────────────────────────

const controlSocketPath = (): string | null => {
  const runtimeDir = process.env.XDG_RUNTIME_DIR;
  if (!runtimeDir) return null;
  return path.join(runtimeDir, "onecli", "control.sock");
};

// ── Injection building ────────────────────────────────────────────────────

/**
 * Build injections for a secret. Mirrors the logic in the Rust gateway's
 * former connect.rs (now handled here, before the push).
 */
const buildInjections = (
  secretType: string,
  decryptedValue: string,
  injectionConfig: unknown,
): Injection[] => {
  if (secretType === "anthropic") {
    const isOauth = decryptedValue.startsWith("sk-ant-oat");
    if (isOauth) {
      return [
        {
          action: "replace_header",
          name: "authorization",
          value: `Bearer ${decryptedValue}`,
        },
      ];
    } else {
      return [
        { action: "set_header", name: "x-api-key", value: decryptedValue },
        { action: "remove_header", name: "authorization" },
      ];
    }
  }

  if (secretType === "generic") {
    const config = injectionConfig as Record<string, string> | null;
    const headerName = config?.headerName;
    if (!headerName) return [];
    const valueFormat = config?.valueFormat;
    const value = valueFormat
      ? valueFormat.replace("{value}", decryptedValue)
      : decryptedValue;
    return [{ action: "set_header", name: headerName, value }];
  }

  return [];
};

// ── Snapshot builder ─────────────────────────────────────────────────────

const buildRulesSnapshot = async (
  accountId: string,
): Promise<RulesSnapshot> => {
  const [agents, allSecrets, allPolicyRules, allAppConnections] =
    await Promise.all([
      db.agent.findMany({
        where: { accountId },
        include: {
          agentSecrets: { select: { secretId: true } },
          agentAppConnections: {
            select: { appConnection: { select: { provider: true } } },
          },
        },
      }),
      db.secret.findMany({ where: { accountId } }),
      db.policyRule.findMany({
        where: { accountId, enabled: true },
      }),
      db.appConnection.findMany({
        where: { accountId, status: "connected" },
        select: { provider: true },
      }),
    ]);

  const agentRules: AgentRules[] = await Promise.all(
    agents.map(async (agent) => {
      // Select secrets based on agent's secret mode.
      const agentSecretIds = new Set(agent.agentSecrets.map((s) => s.secretId));
      const secrets =
        agent.secretMode === "selective"
          ? allSecrets.filter((s) => agentSecretIds.has(s.id))
          : allSecrets;

      // Group secrets by host pattern, building injection rules.
      const hostMap = new Map<string, InjectionRuleConfig[]>();

      for (const secret of secrets) {
        let rules = hostMap.get(secret.hostPattern);
        if (!rules) {
          rules = [];
          hostMap.set(secret.hostPattern, rules);
        }

        let decrypted: string;
        try {
          decrypted = await cryptoService.decrypt(secret.encryptedValue);
        } catch (err) {
          logger.warn(
            { secretId: secret.id, err },
            "gateway-service: failed to decrypt secret, skipping",
          );
          continue;
        }

        const injections = buildInjections(
          secret.type,
          decrypted,
          secret.injectionConfig,
        );
        if (injections.length === 0) continue;

        rules.push({
          path_pattern: secret.pathPattern ?? "*",
          injections,
        });
      }

      const host_rules: HostRule[] = Array.from(hostMap.entries()).map(
        ([host_pattern, injection_rules]) => ({
          host_pattern,
          injection_rules,
        }),
      );

      // Policy rules: global (agentId IS NULL) + agent-specific.
      const policy_rules: PolicyRuleConfig[] = allPolicyRules
        .filter((r) => r.agentId === null || r.agentId === agent.id)
        .map((r) => ({
          rule_id: r.id,
          host_pattern: r.hostPattern,
          path_pattern: r.pathPattern ?? null,
          method: r.method ?? null,
          action: r.action,
          rate_limit: r.rateLimit ?? null,
          rate_limit_window: r.rateLimitWindow ?? null,
        }));

      // App connections: use agent-specific links, or all account connections
      // if no specific links are configured.
      const agentProviders = agent.agentAppConnections.map(
        (aac: { appConnection: { provider: string } }) =>
          aac.appConnection.provider,
      );
      const app_connections: AppConnectionConfig[] = (
        agentProviders.length > 0
          ? agentProviders
          : allAppConnections.map((c) => c.provider)
      ).map((provider: string) => ({ provider }));

      return {
        token: agent.accessToken,
        account_id: accountId,
        host_rules,
        policy_rules,
        app_connections,
      };
    }),
  );

  return { agents: agentRules };
};

// ── HTTP over Unix socket ─────────────────────────────────────────────────

const postToSocket = (socketPath: string, body: string): Promise<void> =>
  new Promise((resolve, reject) => {
    const req = http.request(
      {
        socketPath,
        path: "/rules",
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body),
        },
      },
      (res) => {
        res.resume(); // drain response body
        if (res.statusCode === 200) {
          resolve();
        } else {
          reject(new Error(`control socket returned HTTP ${res.statusCode}`));
        }
      },
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });

// ── Public API ────────────────────────────────────────────────────────────

/**
 * Build the current rules snapshot for an account and push it to the
 * gateway via the Unix control socket.
 *
 * - If the socket path cannot be determined or the socket does not exist,
 *   logs a warning and returns silently.
 * - Never throws; any error is logged as a warning.
 */
export const notifyGateway = async (accountId: string): Promise<void> => {
  const socketPath = controlSocketPath();
  if (!socketPath) return;

  try {
    const snapshot = await buildRulesSnapshot(accountId);
    await postToSocket(socketPath, JSON.stringify(snapshot));
    logger.debug(
      { accountId, agents: snapshot.agents.length },
      "gateway rules pushed",
    );
  } catch (err: unknown) {
    // ENOENT means the gateway is not running — expected in test/CI environments.
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ECONNREFUSED") {
      logger.warn(
        { socketPath },
        "gateway control socket not found; push skipped",
      );
      return;
    }
    logger.warn({ accountId, err }, "gateway push failed");
  }
};
