/**
 * Next.js instrumentation hook — runs once when the server starts.
 *
 * In production, patches console.* to route all output through pino
 * as structured JSON. This captures both our code AND Next.js internal
 * logs (startup, errors, request logging) in a format CloudWatch
 * Insights can parse.
 *
 * In development, console.* is left untouched (pino-pretty handles
 * our explicit logger calls, and Next.js dev output stays readable).
 *
 * Also pushes the current rules snapshot to the gateway on startup so
 * that a gateway restart picks up its configuration without requiring
 * a manual config change.
 */
export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    // Push rules to the gateway for every account on startup.
    // This handles the case where the gateway restarted while the web UI was
    // still running — the gateway starts with empty rules and this push fills it.
    void (async () => {
      try {
        const { db } = await import("@onecli/db");
        const { notifyGateway } =
          await import("@/lib/services/gateway-service");
        const accounts = await db.account.findMany({ select: { id: true } });
        await Promise.all(accounts.map((a) => notifyGateway(a.id)));
      } catch {
        // Startup push is best-effort. Errors are already logged inside notifyGateway.
      }
    })();
  }

  if (
    process.env.NEXT_RUNTIME === "nodejs" &&
    process.env.NODE_ENV === "production"
  ) {
    const pino = (await import("pino")).default;
    const logger = pino({
      level: process.env.LOG_LEVEL ?? "info",
      formatters: {
        level: (label: string) => ({ level: label }),
      },
      timestamp: pino.stdTimeFunctions.isoTime,
    });

    console.log = (...args: unknown[]) =>
      logger.info(args.length === 1 ? args[0] : { msg: args.join(" ") });
    console.info = (...args: unknown[]) =>
      logger.info(args.length === 1 ? args[0] : { msg: args.join(" ") });
    console.warn = (...args: unknown[]) =>
      logger.warn(args.length === 1 ? args[0] : { msg: args.join(" ") });
    console.error = (...args: unknown[]) =>
      logger.error(args.length === 1 ? args[0] : { msg: args.join(" ") });
  }
}
