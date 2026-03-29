import type { Router } from "express";
import jwt from "jsonwebtoken";
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

// --- Extension ---

export default (router: Router, context: any) => {
  const { services, getSchema, database, env } = context;

  router.post("/", async (req: any, res: any) => {
    try {
      const { token, issuer } = req.body;

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

      // 1. Verify token directly with provider
      let userinfo: {
        email: string;
        sub: string;
        given_name?: string;
        family_name?: string;
      };

      if (issuer === "apple") {
        userinfo = await verifyAppleToken(token);
      } else {
        const googleAudience = env.SSO_GOOGLE_CLIENT_ID || "";
        userinfo = await verifyGoogleToken(token, googleAudience);
      }

      // 2. Find or create Directus user
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
      } else {
        const roleId = env.SSO_DEFAULT_ROLE_ID || null;
        userId = await usersService.createOne({
          email: userinfo.email,
          first_name: userinfo.given_name || null,
          last_name: userinfo.family_name || null,
          provider: issuer,
          external_identifier: userinfo.sub,
          role: roleId,
        });
        users = [{ id: userId, role: roleId }];
      }

      // 3. Generate Directus tokens
      const secret = env.SECRET;
      const accessTokenTTL = env.ACCESS_TOKEN_TTL || "15m";
      const sessionTTL = env.REFRESH_TOKEN_TTL || "7d";

      function parseTTL(ttl: string): number {
        const match = ttl.match(/^(\d+)([smhd])$/);
        if (!match) return 900000;
        const num = parseInt(match[1]);
        const unit = match[2];
        if (unit === "s") return num * 1000;
        if (unit === "m") return num * 60 * 1000;
        if (unit === "h") return num * 3600 * 1000;
        if (unit === "d") return num * 86400 * 1000;
        return 900000;
      }

      const accessExpires = parseTTL(accessTokenTTL);
      const sessionToken = nanoid(64);

      // Fetch role permissions
      const user = users[0];
      let appAccess = true;
      let adminAccess = false;
      if (user?.role) {
        const role = await database("directus_roles")
          .where({ id: user.role })
          .first();
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
      console.error("[sso-exchange] Error:", error.message);
      return res.status(401).json({
        errors: [{ message: error.message || "Authentication failed" }],
      });
    }
  });
};
