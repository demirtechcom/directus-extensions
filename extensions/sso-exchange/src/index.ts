import type { Router } from "express";
import { randomUUID, scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";
import jwt from "jsonwebtoken";

const scryptAsync = promisify(scrypt);

async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString("hex");
  const hash = (await scryptAsync(password, salt, 64)) as Buffer;
  return `${salt}:${hash.toString("hex")}`;
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [salt, hash] = stored.split(":");
  if (!salt || !hash) return false;
  const hashBuffer = Buffer.from(hash, "hex");
  const derived = (await scryptAsync(password, salt, 64)) as Buffer;
  return timingSafeEqual(hashBuffer, derived);
}
import jwksClient from "jwks-rsa";
import { nanoid } from "nanoid";

// --- Apple token verification ---

const appleJwks = jwksClient({
  jwksUri: "https://appleid.apple.com/auth/keys",
  cache: true,
  cacheMaxAge: 3600_000,
});

function verifyAppleToken(
  idToken: string,
): Promise<{ email: string; sub: string }> {
  return new Promise((resolve, reject) => {
    jwt.verify(
      idToken,
      (header, callback) => {
        appleJwks.getSigningKey(header.kid!, (err, key) => {
          if (err) return callback(err);
          callback(null, key!.getPublicKey());
        });
      },
      { issuer: "https://appleid.apple.com", algorithms: ["RS256"] },
      (err, decoded: any) => {
        if (err) return reject(new Error("Invalid Apple token"));
        if (!decoded?.email) return reject(new Error("No email in Apple token"));
        resolve({ email: decoded.email, sub: decoded.sub });
      },
    );
  });
}

// --- Google token verification ---

async function verifyGoogleToken(
  idToken: string,
  expectedAudience: string,
): Promise<{ email: string; sub: string; given_name?: string; family_name?: string }> {
  const res = await fetch(
    `https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`,
  );
  if (!res.ok) throw new Error("Invalid Google token");

  const data = (await res.json()) as {
    email: string;
    sub: string;
    given_name?: string;
    family_name?: string;
    aud: string;
    email_verified: string;
  };

  if (!data.email) throw new Error("No email in Google token");
  if (data.email_verified !== "true") throw new Error("Google email not verified");
  if (expectedAudience && data.aud !== expectedAudience) {
    throw new Error("Google token audience mismatch");
  }

  return data;
}

// --- Shared helpers ---

function parseTTL(ttl: string): number {
  const match = ttl.match(/^(\d+)([smhd])$/);
  if (!match) return 900_000;
  const num = parseInt(match[1]);
  const unit = match[2];
  if (unit === "s") return num * 1_000;
  if (unit === "m") return num * 60_000;
  if (unit === "h") return num * 3_600_000;
  if (unit === "d") return num * 86_400_000;
  return 900_000;
}

// --- In-memory rate limiter ---

interface RateEntry {
  count: number;
  windowStart: number;
}

const loginAttempts = new Map<string, RateEntry>();

function checkRateLimit(ip: string, maxAttempts: number, windowMs: number): boolean {
  const now = Date.now();
  const entry = loginAttempts.get(ip);
  if (!entry || now - entry.windowStart > windowMs) return true;
  return entry.count < maxAttempts;
}

function recordFailedAttempt(ip: string, windowMs: number): void {
  const now = Date.now();
  const entry = loginAttempts.get(ip);
  if (!entry || now - entry.windowStart > windowMs) {
    loginAttempts.set(ip, { count: 1, windowStart: now });
  } else {
    entry.count++;
  }
}

function resetRateLimit(ip: string): void {
  loginAttempts.delete(ip);
}

// --- Extension ---

export default (router: Router, context: any) => {
  const { services, getSchema, database, env, logger } = context;

  const rawOrigins = env.SSO_WEB_ALLOWED_ORIGINS || "";
  const allowedOrigins = (Array.isArray(rawOrigins) ? rawOrigins : rawOrigins.split(",")).map((s: string) => s.trim()).filter(Boolean);
  logger.info(`[sso-exchange] SSO_WEB_ALLOWED_ORIGINS type=${typeof rawOrigins} isArray=${Array.isArray(rawOrigins)} raw=${JSON.stringify(rawOrigins)} parsed=${JSON.stringify(allowedOrigins)}`);

  // --- Ensure username column exists on directus_users (fire-and-forget) ---
  (async () => {
    try {
      const hasUsername = await database.schema.hasColumn("directus_users", "username");
      if (!hasUsername) {
        await database.schema.table("directus_users", (t: any) => {
          t.string("username", 64).nullable();
          t.unique(["username"], { indexName: "idx_directus_users_username" });
        });
        logger.info("[sso-exchange] Created username column on directus_users");
      }
    } catch (err: any) {
      logger.warn(`[sso-exchange] Username column migration skipped: ${err.message}`);
    }
  })();

  const rateLimitMax = parseInt(env.CREDENTIALS_RATE_LIMIT_MAX || "5");
  const rateLimitWindowMs = parseTTL(env.CREDENTIALS_RATE_LIMIT_WINDOW || "15m");

  // --- Refresh endpoint ---
  router.post("/refresh", async (req: any, res: any) => {
    try {
      const { refresh_token } = req.body;
      if (!refresh_token) {
        return res.status(400).json({ errors: [{ message: "refresh_token is required" }] });
      }

      const session = await database("directus_sessions")
        .where({ token: refresh_token })
        .andWhere("expires", ">", new Date())
        .first();

      if (!session) {
        return res.status(401).json({ errors: [{ message: "Invalid or expired refresh token" }] });
      }

      const schema = await getSchema();
      const { UsersService } = services;
      const usersService = new UsersService({ schema, knex: database });
      const users = await usersService.readByQuery({
        filter: { id: { _eq: session.user } },
        limit: 1,
      });

      if (!users.length) {
        return res.status(401).json({ errors: [{ message: "User not found" }] });
      }

      const user = users[0];
      const secret = env.SECRET;
      const accessTokenTTL = env.ACCESS_TOKEN_TTL || "15m";
      const sessionTTL = env.REFRESH_TOKEN_TTL || "7d";

      const newSessionToken = nanoid(64);

      let appAccess = true;
      let adminAccess = false;
      if (user.role) {
        const role = await database("directus_roles").where({ id: user.role }).first();
        if (role) {
          appAccess = role.app_access ?? true;
          adminAccess = role.admin_access ?? false;
        }
      }

      const accessToken = jwt.sign(
        {
          id: user.id,
          role: user.role ?? null,
          app_access: appAccess,
          admin_access: adminAccess,
          session: newSessionToken,
        },
        secret,
        { expiresIn: accessTokenTTL, issuer: "directus" },
      );

      await database("directus_sessions").where({ token: refresh_token }).del();
      await database("directus_sessions").insert({
        token: newSessionToken,
        user: user.id,
        expires: new Date(Date.now() + parseTTL(sessionTTL)),
        ip: req.ip,
        user_agent: req.headers["user-agent"] || "sso-exchange",
        origin: req.headers["origin"] || null,
      });

      return res.json({
        data: {
          access_token: accessToken,
          refresh_token: newSessionToken,
          expires: parseTTL(accessTokenTTL),
        },
      });
    } catch (error: any) {
      logger.error(`[sso-exchange] Refresh error: ${error.message}`);
      return res.status(500).json({ errors: [{ message: "Refresh failed" }] });
    }
  });

  // --- Web SSO callback ---
  router.get("/web-callback", async (req: any, res: any) => {
    try {
      const appUrl = req.query.app_url;
      if (!appUrl) {
        return res.status(400).send("app_url query parameter is required");
      }

      const appOrigin = new URL(appUrl).origin;
      if (allowedOrigins.length > 0 && !allowedOrigins.includes(appOrigin)) {
        return res.status(400).send("app_url origin not allowed");
      }

      const sessionCookie = req.cookies?.directus_session_token;
      if (!sessionCookie) {
        return res.redirect(`${appUrl}?error=no_session`);
      }

      const decoded = jwt.decode(sessionCookie) as { id?: string; session?: string } | null;
      if (!decoded?.id) {
        return res.redirect(`${appUrl}?error=invalid_session`);
      }

      const schema = await getSchema();
      const { UsersService } = services;
      const usersService = new UsersService({ schema, knex: database });
      const users = await usersService.readByQuery({
        filter: { id: { _eq: decoded.id } },
        limit: 1,
      });

      if (!users.length) {
        return res.redirect(`${appUrl}?error=user_not_found`);
      }

      const user = users[0];
      const secret = env.SECRET;
      const accessTokenTTL = env.ACCESS_TOKEN_TTL || "15m";
      const sessionTTL = env.REFRESH_TOKEN_TTL || "7d";
      const sessionToken = nanoid(64);

      let appAccess = true;
      let adminAccess = false;
      if (user.role) {
        const role = await database("directus_roles").where({ id: user.role }).first();
        if (role) {
          appAccess = role.app_access ?? true;
          adminAccess = role.admin_access ?? false;
        }
      }

      const accessToken = jwt.sign(
        {
          id: user.id,
          role: user.role ?? null,
          app_access: appAccess,
          admin_access: adminAccess,
          session: sessionToken,
        },
        secret,
        { expiresIn: accessTokenTTL, issuer: "directus" },
      );

      await database("directus_sessions").insert({
        token: sessionToken,
        user: user.id,
        expires: new Date(Date.now() + parseTTL(sessionTTL)),
        ip: req.ip,
        user_agent: req.headers["user-agent"] || "sso-exchange-web",
        origin: appOrigin,
      });

      const params = new URLSearchParams({
        access_token: accessToken,
        refresh_token: sessionToken,
        expires: String(parseTTL(accessTokenTTL)),
      });

      return res.redirect(`${appUrl}#${params.toString()}`);
    } catch (error: any) {
      logger.error(`[sso-exchange] Web callback error: ${error.message}`);
      return res.status(500).send("Authentication failed");
    }
  });

  // --- Delete account endpoint ---
  router.delete("/delete-account", async (req: any, res: any) => {
    try {
      const authHeader = req.headers["authorization"];
      if (!authHeader?.startsWith("Bearer ")) {
        return res.status(401).json({ errors: [{ message: "Authorization header required" }] });
      }
      const token = authHeader.slice(7);

      const secret = env.SECRET;
      let decoded: { id?: string };
      try {
        decoded = jwt.verify(token, secret, { issuer: "directus" }) as { id?: string };
      } catch {
        return res.status(401).json({ errors: [{ message: "Invalid or expired token" }] });
      }

      if (!decoded?.id) {
        return res.status(401).json({ errors: [{ message: "Invalid token payload" }] });
      }

      const userId = decoded.id;
      const user = await database("directus_users").where({ id: userId }).first();
      if (!user) {
        return res.status(404).json({ status: "not_found" });
      }

      if (user.status === "archived") {
        return res.json({ status: "deleted" });
      }

      await database.transaction(async (trx: any) => {
        await trx("directus_sessions").where({ user: userId }).del();
        await trx("directus_users")
          .where({ id: userId })
          .update({
            status: "archived",
            external_identifier: null,
            email: `deleted_${userId}@deleted.local`,
          });
      });

      logger.info(`[sso-exchange] User ${userId} soft-deleted their account`);
      return res.json({ status: "deleted" });
    } catch (error: any) {
      logger.error(`[sso-exchange] Delete account error: ${error.message}`);
      return res.status(500).json({ errors: [{ message: "Account deletion failed" }] });
    }
  });

  // --- Logout endpoint ---
  router.get("/logout", (req: any, res: any) => {
    const redirectUrl = req.query.redirect_url;
    if (!redirectUrl) {
      return res.status(400).json({ errors: [{ message: "redirect_url is required" }] });
    }

    try {
      const origin = new URL(redirectUrl).origin;
      if (allowedOrigins.length > 0 && !allowedOrigins.includes(origin)) {
        return res.status(400).json({ errors: [{ message: "redirect_url origin not allowed" }] });
      }
    } catch {
      return res.status(400).json({ errors: [{ message: "Invalid redirect_url" }] });
    }

    res.clearCookie("directus_session_token", { path: "/" });

    const keycloakIssuerRaw = env.AUTH_KEYCLOAK_ISSUER_URL || "";
    const keycloakIssuer = keycloakIssuerRaw.replace(/\/\.well-known\/openid-configuration$/, "");
    const keycloakClientId = env.AUTH_KEYCLOAK_CLIENT_ID;

    if (!keycloakIssuer || !keycloakClientId) {
      return res.redirect(redirectUrl);
    }

    const logoutUrl = new URL(`${keycloakIssuer}/protocol/openid-connect/logout`);
    logoutUrl.searchParams.set("post_logout_redirect_uri", redirectUrl);
    logoutUrl.searchParams.set("client_id", keycloakClientId);

    return res.redirect(logoutUrl.toString());
  });

  router.post("/credentials/register", async (req: any, res: any) => {
    try {
      const { username, password, email, first_name, last_name } = req.body;

      if (!username || typeof username !== "string") {
        return res.status(400).json({ errors: [{ message: "username is required" }] });
      }
      if (!/^[a-zA-Z0-9_-]{3,32}$/.test(username)) {
        return res.status(400).json({ errors: [{ message: "username must be 3–32 characters (letters, numbers, _ or -)" }] });
      }
      if (!password || typeof password !== "string" || password.length < 8) {
        return res.status(400).json({ errors: [{ message: "password must be at least 8 characters" }] });
      }
      if (!email || typeof email !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ errors: [{ message: "valid email is required" }] });
      }

      const existingUsername = await database("directus_users").where({ username }).select("id").first();
      if (existingUsername) {
        return res.status(409).json({ errors: [{ message: "Username already taken", extensions: { code: "USERNAME_TAKEN" } }] });
      }

      const existingEmail = await database("directus_users").where({ email }).select("id").first();
      if (existingEmail) {
        return res.status(409).json({ errors: [{ message: "Email already registered", extensions: { code: "EMAIL_TAKEN" } }] });
      }

      const userId = randomUUID();
      await database("directus_users").insert({
        id: userId,
        username,
        email,
        password: await hashPassword(password),
        status: "active",
        first_name: first_name || null,
        last_name: last_name || null,
        role: env.SSO_DEFAULT_ROLE_ID || null,
        provider: "default",
        token: null,
      });

      logger.info(`[sso-exchange] New credentials user registered: ${userId}`);
      return res.status(201).json({ data: { id: userId, username } });
    } catch (error: any) {
      logger.error(`[sso-exchange] Register error: ${error.message}`);
      return res.status(500).json({ errors: [{ message: "Registration failed" }] });
    }
  });

  router.post("/credentials/login", async (req: any, res: any) => {
    const ip = (req.ip as string) || "unknown";
    const INVALID_CREDS = {
      errors: [{ message: "Invalid credentials", extensions: { code: "INVALID_CREDENTIALS" } }],
    };

    try {
      const { username, password } = req.body;
      if (!username || typeof username !== "string" || !password || typeof password !== "string") {
        return res.status(400).json({ errors: [{ message: "username and password are required" }] });
      }

      if (!checkRateLimit(ip, rateLimitMax, rateLimitWindowMs)) {
        return res.status(429).json({
          errors: [{ message: "Too many login attempts. Try again later.", extensions: { code: "RATE_LIMIT_EXCEEDED" } }],
        });
      }

      const userRow = await database("directus_users")
        .where({ username })
        .select("id", "status", "role", "password")
        .first();

      if (!userRow || userRow.status !== "active") {
        recordFailedAttempt(ip, rateLimitWindowMs);
        return res.status(401).json(INVALID_CREDS);
      }

      if (!userRow.password || !(await verifyPassword(password, userRow.password))) {
        recordFailedAttempt(ip, rateLimitWindowMs);
        return res.status(401).json(INVALID_CREDS);
      }

      const secret = env.SECRET;
      const accessTokenTTL = env.ACCESS_TOKEN_TTL || "15m";
      const sessionTTL = env.REFRESH_TOKEN_TTL || "7d";
      const sessionToken = nanoid(64);

      let appAccess = true;
      let adminAccess = false;
      if (userRow.role) {
        const role = await database("directus_roles").where({ id: userRow.role }).first();
        if (role) {
          appAccess = role.app_access ?? true;
          adminAccess = role.admin_access ?? false;
        }
      }

      const accessToken = jwt.sign(
        {
          id: userRow.id,
          role: userRow.role ?? null,
          app_access: appAccess,
          admin_access: adminAccess,
          session: sessionToken,
        },
        secret,
        { expiresIn: accessTokenTTL, issuer: "directus" },
      );

      await database("directus_sessions").insert({
        token: sessionToken,
        user: userRow.id,
        expires: new Date(Date.now() + parseTTL(sessionTTL)),
        ip,
        user_agent: req.headers["user-agent"] || "sso-exchange",
        origin: req.headers["origin"] || null,
      });

      resetRateLimit(ip);
      return res.json({
        data: {
          access_token: accessToken,
          refresh_token: sessionToken,
          expires: parseTTL(accessTokenTTL),
        },
      });
    } catch (error: any) {
      logger.error(`[sso-exchange] Credentials login error: ${error.message}`);
      return res.status(500).json({ errors: [{ message: "Login failed" }] });
    }
  });

  // --- SSO login (Apple / Google) ---
  router.post("/", async (req: any, res: any) => {
    try {
      const { token, issuer, given_name: clientGivenName, family_name: clientFamilyName } = req.body;

      if (!token || !issuer) {
        return res.status(400).json({
          errors: [{ message: "token and issuer are required" }],
        });
      }

      if (issuer !== "apple" && issuer !== "google") {
        return res.status(400).json({
          errors: [{ message: "issuer must be 'apple' or 'google'" }],
        });
      }

      let userinfo: {
        email: string;
        sub: string;
        given_name?: string;
        family_name?: string;
      };

      if (issuer === "apple") {
        userinfo = await verifyAppleToken(token);
        if (clientGivenName) userinfo.given_name = clientGivenName;
        if (clientFamilyName) userinfo.family_name = clientFamilyName;
      } else {
        const googleAudience = env.SSO_GOOGLE_CLIENT_ID || "";
        userinfo = await verifyGoogleToken(token, googleAudience);
      }

      const schema = await getSchema();
      const { UsersService } = services;
      const usersService = new UsersService({ schema, knex: database });

      let users = await usersService.readByQuery({
        filter: { email: { _eq: userinfo.email } },
        limit: 1,
      });

      let userId: string;

      if (users.length > 0) {
        userId = users[0].id;

        const existing = users[0];
        const nameUpdate: Record<string, string> = {};
        if (!existing.first_name && userinfo.given_name) nameUpdate.first_name = userinfo.given_name;
        if (!existing.last_name && userinfo.family_name) nameUpdate.last_name = userinfo.family_name;
        if (Object.keys(nameUpdate).length > 0) {
          await usersService.updateOne(userId, nameUpdate);
        }
      } else {
        const roleId = env.SSO_DEFAULT_ROLE_ID || null;
        userId = await usersService.createOne({
          email: userinfo.email,
          first_name: userinfo.given_name || null,
          last_name: userinfo.family_name || null,
          external_identifier: userinfo.sub,
          role: roleId,
        });
        users = [{ id: userId, role: roleId }];
      }

      const secret = env.SECRET;
      const accessTokenTTL = env.ACCESS_TOKEN_TTL || "15m";
      const sessionTTL = env.REFRESH_TOKEN_TTL || "7d";
      const accessExpires = parseTTL(accessTokenTTL);
      const sessionToken = nanoid(64);

      const user = users[0];
      let appAccess = true;
      let adminAccess = false;
      if (user?.role) {
        const role = await database("directus_roles").where({ id: user.role }).first();
        if (role) {
          appAccess = role.app_access ?? true;
          adminAccess = role.admin_access ?? false;
        }
      }

      const accessToken = jwt.sign(
        {
          id: userId,
          role: user?.role ?? null,
          app_access: appAccess,
          admin_access: adminAccess,
          session: sessionToken,
        },
        secret,
        { expiresIn: accessTokenTTL, issuer: "directus" },
      );

      await database("directus_sessions").insert({
        token: sessionToken,
        user: userId,
        expires: new Date(Date.now() + parseTTL(sessionTTL)),
        ip: req.ip,
        user_agent: req.headers["user-agent"] || "sso-exchange",
        origin: req.headers["origin"] || null,
      });

      return res.json({
        data: {
          access_token: accessToken,
          refresh_token: sessionToken,
          expires: accessExpires,
        },
      });
    } catch (error: any) {
      logger.error(`[sso-exchange] SSO error: ${error.message}`);
      return res.status(401).json({
        errors: [{ message: error.message || "Authentication failed" }],
      });
    }
  });
};
