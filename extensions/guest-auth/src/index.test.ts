import assert from "node:assert/strict";
import { describe, it } from "node:test";
import jwt from "jsonwebtoken";

import registerGuestAuth from "./index";

const GUEST_ID = "550e8400-e29b-41d4-a716-446655440000";

type RouteHandler = (request: Request, response: Response) => Promise<unknown>;

interface Request {
  body?: Record<string, unknown>;
  headers: Record<string, string | undefined>;
  ip?: string;
}

interface ResponseBody {
  data?: {
    access_token: string;
    refresh_token: string;
    expires: number;
  };
  errors?: Array<{ extensions?: { code?: string }; message: string }>;
}

interface Response {
  json: (body: ResponseBody) => ResponseBody;
  status: (status: number) => Response;
}

interface GuestUser {
  id: string;
  role: string | null;
  status: string;
}

function setup(options?: {
  existingUser?: GuestUser;
  role?: Record<string, unknown> | null;
  env?: Record<string, unknown>;
}) {
  const routes = new Map<string, RouteHandler>();
  const createdUsers: Record<string, unknown>[] = [];
  const sessions: Record<string, unknown>[] = [];
  const logs: string[] = [];
  let existingUser = options?.existingUser;

  const router = {
    post: (path: string, handler: RouteHandler) => routes.set(`POST ${path}`, handler),
  };

  const database = (table: string) => {
    if (table === "directus_sessions") {
      return {
        insert: async (value: Record<string, unknown>) => {
          sessions.push(value);
        },
      };
    }

    if (table === "directus_roles") {
      return {
        where: () => ({
          select: () => ({
            first: async () =>
              options?.role === undefined
                ? { id: "guest-role", app_access: false, admin_access: false }
                : options.role,
          }),
        }),
      };
    }

    throw new Error(`Unexpected table: ${table}`);
  };

  class UsersService {
    async readByQuery(): Promise<GuestUser[]> {
      return existingUser ? [existingUser] : [];
    }

    async createOne(value: Record<string, unknown>): Promise<string> {
      createdUsers.push(value);
      existingUser = { id: "guest-user", role: String(value.role), status: "active" };
      return existingUser.id;
    }
  }

  registerGuestAuth(router as never, {
    database: database as never,
    env: {
      ACCESS_TOKEN_TTL: "15m",
      GUEST_ROLE_ID: "guest-role",
      REFRESH_TOKEN_TTL: "7d",
      SECRET: "test-secret",
      ...options?.env,
    },
    getSchema: async () => ({}),
    logger: {
      error: (message: string) => logs.push(message),
      info: (message: string) => logs.push(message),
      warn: (message: string) => logs.push(message),
    },
    services: { UsersService },
  });

  const handler = routes.get("POST /");
  if (!handler) throw new Error("POST / route was not registered");

  let statusCode = 200;
  let body: ResponseBody | undefined;
  const response: Response = {
    json: (value) => {
      body = value;
      return value;
    },
    status: (value) => {
      statusCode = value;
      return response;
    },
  };

  return {
    createdUsers,
    getBody: () => body,
    getStatus: () => statusCode,
    handler,
    logs,
    response,
    sessions,
  };
}

describe("guest-auth", () => {
  it("rejects an invalid guest id without creating a user", async () => {
    const test = setup();

    await test.handler(
      { body: { guest_id: "not-a-uuid" }, headers: {}, ip: "invalid-id" },
      test.response,
    );

    assert.equal(test.getStatus(), 400);
    assert.equal(test.getBody()?.errors?.[0]?.extensions?.code, "INVALID_GUEST_ID");
    assert.equal(test.createdUsers.length, 0);
    assert.equal(test.sessions.length, 0);
  });

  it("creates a restricted guest and returns Directus tokens", async () => {
    const test = setup();

    await test.handler(
      {
        body: { guest_id: GUEST_ID },
        headers: { origin: "https://www.kayseriyemek.com", "user-agent": "test-agent" },
        ip: "creates-guest",
      },
      test.response,
    );

    assert.equal(test.getStatus(), 200);
    assert.deepEqual(test.createdUsers, [
      {
        email: `guest-${GUEST_ID}@guest.kayseriyemek.invalid`,
        external_identifier: `guest:${GUEST_ID}`,
        first_name: "Guest",
        last_name: null,
        role: "guest-role",
        status: "active",
      },
    ]);
    assert.equal(test.sessions.length, 1);
    assert.equal(test.sessions[0]?.user, "guest-user");
    assert.equal(test.sessions[0]?.origin, "https://www.kayseriyemek.com");
    assert.equal(typeof test.getBody()?.data?.refresh_token, "string");
    assert.equal(test.getBody()?.data?.expires, 900_000);

    const decoded = jwt.verify(test.getBody()?.data?.access_token ?? "", "test-secret", {
      issuer: "directus",
    }) as jwt.JwtPayload;
    assert.equal(decoded.id, "guest-user");
    assert.equal(decoded.role, "guest-role");
    assert.equal(decoded.admin_access, false);
  });

  it("reuses an existing active guest instead of creating another user", async () => {
    const test = setup({
      existingUser: { id: "existing-guest", role: "guest-role", status: "active" },
    });

    await test.handler(
      { body: { guest_id: GUEST_ID }, headers: {}, ip: "existing-guest" },
      test.response,
    );

    assert.equal(test.getStatus(), 200);
    assert.equal(test.createdUsers.length, 0);
    assert.equal(test.sessions[0]?.user, "existing-guest");
  });

  it("does not issue a session for an archived guest", async () => {
    const test = setup({
      existingUser: { id: "archived-guest", role: "guest-role", status: "archived" },
    });

    await test.handler(
      { body: { guest_id: GUEST_ID }, headers: {}, ip: "archived-guest" },
      test.response,
    );

    assert.equal(test.getStatus(), 403);
    assert.equal(test.getBody()?.errors?.[0]?.extensions?.code, "GUEST_ACCOUNT_DISABLED");
    assert.equal(test.sessions.length, 0);
  });

  it("does not issue a token when an existing guest has a different role", async () => {
    const test = setup({
      existingUser: { id: "role-changed-guest", role: "business-role", status: "active" },
    });

    await test.handler(
      { body: { guest_id: GUEST_ID }, headers: {}, ip: "role-changed-guest" },
      test.response,
    );

    assert.equal(test.getStatus(), 403);
    assert.equal(test.getBody()?.errors?.[0]?.extensions?.code, "GUEST_ROLE_MISMATCH");
    assert.equal(test.sessions.length, 0);
  });

  it("fails closed when the configured role has administrator access", async () => {
    const test = setup({ role: { id: "admin-role", app_access: true, admin_access: true } });

    await test.handler({ body: { guest_id: GUEST_ID }, headers: {}, ip: "admin-role" }, test.response);

    assert.equal(test.getStatus(), 503);
    assert.equal(test.getBody()?.errors?.[0]?.extensions?.code, "GUEST_ROLE_INVALID");
    assert.equal(test.createdUsers.length, 0);
    assert.equal(test.sessions.length, 0);
  });

  it("rate limits repeated attempts from one IP", async () => {
    const test = setup({ env: { GUEST_AUTH_RATE_LIMIT_MAX: "1" } });
    const request = { body: { guest_id: GUEST_ID }, headers: {}, ip: "rate-limited" };

    await test.handler(request, test.response);
    await test.handler(request, test.response);

    assert.equal(test.getStatus(), 429);
    assert.equal(test.getBody()?.errors?.[0]?.extensions?.code, "RATE_LIMIT_EXCEEDED");
    assert.equal(test.sessions.length, 1);
  });
});
