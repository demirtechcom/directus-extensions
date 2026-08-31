import type { Router } from "express";
import jwt, { type SignOptions } from "jsonwebtoken";
import { nanoid } from "nanoid";

const GUEST_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const GUEST_USER_FIELDS = ["id", "role", "status"];

interface RateEntry {
  count: number;
  windowStart: number;
}

interface GuestUser {
  id: string;
  role: string | null;
  status: string;
}

interface GuestAuthContext {
  database: Database;
  env: Record<string, unknown>;
  getSchema: () => Promise<unknown>;
  logger: Logger;
  services: {
    UsersService: new (options: { schema: unknown; knex: Database }) => UsersService;
  };
}

interface Database {
  (table: string): QueryBuilder;
}

interface QueryBuilder {
  first: () => Promise<Record<string, unknown> | undefined>;
  insert: (value: Record<string, unknown>) => Promise<unknown>;
  select: (...fields: string[]) => QueryBuilder;
  where: (filter: Record<string, unknown>) => QueryBuilder;
}

interface Logger {
  error: (message: string) => void;
  info: (message: string) => void;
  warn: (message: string) => void;
}

interface UsersService {
  createOne: (value: Record<string, unknown>) => Promise<string>;
  readByQuery: (query: Record<string, unknown>) => Promise<GuestUser[]>;
}

const attempts = new Map<string, RateEntry>();

function parseTTL(value: unknown, fallback: string): number {
  const ttl = typeof value === "string" ? value : fallback;
  const match = ttl.match(/^(\d+)([smhd])$/);
  if (!match) return parseTTL(fallback, "15m");

  const amount = Number(match[1]);
  const unit = match[2];
  if (unit === "s") return amount * 1_000;
  if (unit === "m") return amount * 60_000;
  if (unit === "h") return amount * 3_600_000;
  return amount * 86_400_000;
}

function positiveInteger(value: unknown, fallback: number): number {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function consumeRateLimit(ip: string, maxAttempts: number, windowMs: number): boolean {
  const now = Date.now();
  const entry = attempts.get(ip);

  if (!entry || now - entry.windowStart >= windowMs) {
    attempts.set(ip, { count: 1, windowStart: now });
    return true;
  }

  if (entry.count >= maxAttempts) return false;
  entry.count += 1;
  return true;
}

function guestExternalIdentifier(guestId: string): string {
  return `guest:${guestId.toLowerCase()}`;
}

function guestEmail(guestId: string): string {
  return `guest-${guestId.toLowerCase()}@guest.kayseriyemek.invalid`;
}

export default (router: Router, context: GuestAuthContext): void => {
  const { database, env, getSchema, logger, services } = context;
  const rateLimitMax = positiveInteger(env.GUEST_AUTH_RATE_LIMIT_MAX, 20);
  const rateLimitWindowMs = parseTTL(env.GUEST_AUTH_RATE_LIMIT_WINDOW, "15m");

  router.post("/", async (request, response) => {
    const ip = request.ip || "unknown";

    if (!consumeRateLimit(ip, rateLimitMax, rateLimitWindowMs)) {
      return response.status(429).json({
        errors: [
          {
            message: "Too many guest authentication attempts. Try again later.",
            extensions: { code: "RATE_LIMIT_EXCEEDED" },
          },
        ],
      });
    }

    const guestId = request.body?.guest_id;
    if (typeof guestId !== "string" || !GUEST_ID_PATTERN.test(guestId)) {
      return response.status(400).json({
        errors: [
          {
            message: "guest_id must be a valid UUID",
            extensions: { code: "INVALID_GUEST_ID" },
          },
        ],
      });
    }

    const secret = typeof env.SECRET === "string" ? env.SECRET : "";
    const configuredRole = env.GUEST_ROLE_ID || env.SSO_DEFAULT_ROLE_ID;
    const roleId = typeof configuredRole === "string" ? configuredRole : "";
    if (!secret || !roleId) {
      logger.error("[guest-auth] SECRET or guest role is not configured");
      return response.status(503).json({
        errors: [
          {
            message: "Guest authentication is unavailable",
            extensions: { code: "GUEST_AUTH_UNAVAILABLE" },
          },
        ],
      });
    }

    try {
      const role = await database("directus_roles")
        .where({ id: roleId })
        .select("id", "app_access", "admin_access")
        .first();
      if (!role || role.admin_access === true) {
        logger.error("[guest-auth] Guest role is missing or has administrator access");
        return response.status(503).json({
          errors: [
            {
              message: "Guest authentication is unavailable",
              extensions: { code: "GUEST_ROLE_INVALID" },
            },
          ],
        });
      }

      const schema = await getSchema();
      const usersService = new services.UsersService({ schema, knex: database });
      const externalIdentifier = guestExternalIdentifier(guestId);
      let users = await usersService.readByQuery({
        filter: { external_identifier: { _eq: externalIdentifier } },
        fields: GUEST_USER_FIELDS,
        limit: 1,
      });

      let user = users[0];
      if (user && user.status !== "active") {
        return response.status(403).json({
          errors: [
            {
              message: "Guest account is unavailable",
              extensions: { code: "GUEST_ACCOUNT_DISABLED" },
            },
          ],
        });
      }
      if (user && user.role !== roleId) {
        logger.error("[guest-auth] Existing guest no longer has the configured guest role");
        return response.status(403).json({
          errors: [
            {
              message: "Guest account is unavailable",
              extensions: { code: "GUEST_ROLE_MISMATCH" },
            },
          ],
        });
      }

      if (!user) {
        try {
          const userId = await usersService.createOne({
            email: guestEmail(guestId),
            external_identifier: externalIdentifier,
            first_name: "Guest",
            last_name: null,
            role: roleId,
            status: "active",
          });
          user = { id: userId, role: roleId, status: "active" };
          logger.info(`[guest-auth] Created guest user ${userId}`);
        } catch (error: unknown) {
          // A concurrent request can win the create. Re-read before treating the
          // unique external identifier collision as an authentication failure.
          users = await usersService.readByQuery({
            filter: { external_identifier: { _eq: externalIdentifier } },
            fields: GUEST_USER_FIELDS,
            limit: 1,
          });
          user = users[0];
          if (!user || user.status !== "active") throw error;
        }
      }

      const accessTokenTTL = (typeof env.ACCESS_TOKEN_TTL === "string"
        ? env.ACCESS_TOKEN_TTL
        : "15m") as SignOptions["expiresIn"];
      const refreshTokenTTL = parseTTL(env.REFRESH_TOKEN_TTL, "7d");
      const accessExpires = parseTTL(accessTokenTTL, "15m");
      const sessionToken = nanoid(64);
      const accessToken = jwt.sign(
        {
          id: user.id,
          role: user.role,
          app_access: role.app_access ?? false,
          admin_access: false,
        },
        secret,
        { expiresIn: accessTokenTTL, issuer: "directus" },
      );

      await database("directus_sessions").insert({
        token: sessionToken,
        user: user.id,
        expires: new Date(Date.now() + refreshTokenTTL),
        ip,
        user_agent: request.headers["user-agent"] || "guest-auth",
        origin: request.headers.origin || null,
      });

      return response.json({
        data: {
          access_token: accessToken,
          refresh_token: sessionToken,
          expires: accessExpires,
        },
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Unknown error";
      logger.error(`[guest-auth] Authentication failed: ${message}`);
      return response.status(500).json({
        errors: [
          {
            message: "Guest authentication failed",
            extensions: { code: "GUEST_AUTH_FAILED" },
          },
        ],
      });
    }
  });
};
