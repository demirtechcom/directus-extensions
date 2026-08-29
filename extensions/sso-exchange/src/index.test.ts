import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";

import registerSsoExchange from "./index";

type RouteHandler = (request: unknown, response: unknown) => Promise<unknown>;

interface JsonResponse {
  data?: {
    access_token?: string;
    refresh_token?: string;
  };
  errors?: Array<{ message: string }>;
}

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe("SSO user lookup", () => {
  it("logs in when unrelated custom directus_users columns are absent", async () => {
    const routes = new Map<string, RouteHandler>();
    const router = {
      delete: (path: string, handler: RouteHandler) => routes.set(`DELETE ${path}`, handler),
      get: (path: string, handler: RouteHandler) => routes.set(`GET ${path}`, handler),
      post: (path: string, handler: RouteHandler) => routes.set(`POST ${path}`, handler),
    };

    const database = Object.assign(
      (table: string) => {
        if (table !== "directus_sessions") {
          throw new Error(`Unexpected table: ${table}`);
        }
        return {
          insert: async () => undefined,
        };
      },
      {
        schema: {
          hasColumn: async () => true,
        },
      },
    );
    let queriedFields: string[] | undefined;

    class UsersService {
      async readByQuery(query: { fields?: string[] }): Promise<unknown[]> {
        queriedFields = query.fields;
        const availableFields = new Set(["id", "role", "first_name", "last_name"]);
        if (!query.fields || query.fields.some((field) => !availableFields.has(field))) {
          throw new Error("column directus_users.phone does not exist");
        }
        return [
          {
            id: "user-1",
            role: null,
            first_name: "Ada",
            last_name: "Lovelace",
          },
        ];
      }
    }

    globalThis.fetch = async () =>
      new Response(
        JSON.stringify({
          aud: "google-web-client",
          email: "ada@example.com",
          email_verified: "true",
          given_name: "Ada",
          family_name: "Lovelace",
          sub: "google-user-1",
        }),
        { headers: { "content-type": "application/json" }, status: 200 },
      );

    registerSsoExchange(router as never, {
      database,
      env: {
        ACCESS_TOKEN_TTL: "15m",
        REFRESH_TOKEN_TTL: "7d",
        SECRET: "test-secret",
        SSO_GOOGLE_CLIENT_IDS: "google-web-client",
      },
      getSchema: async () => ({}),
      logger: {
        error: () => undefined,
        info: () => undefined,
        warn: () => undefined,
      },
      services: { UsersService },
    });

    const handler = routes.get("POST /");
    if (!handler) throw new Error("POST / route was not registered");

    let statusCode = 200;
    let body: JsonResponse | undefined;
    const response = {
      json: (value: JsonResponse) => {
        body = value;
        return value;
      },
      status: (value: number) => {
        statusCode = value;
        return response;
      },
    };

    await handler(
      {
        body: { issuer: "google", token: "valid-google-token" },
        headers: {},
        ip: "127.0.0.1",
      },
      response,
    );

    assert.equal(statusCode, 200);
    assert.deepEqual(queriedFields, ["id", "role", "first_name", "last_name"]);
    assert.equal(body?.errors, undefined);
    assert.equal(typeof body?.data?.access_token, "string");
    assert.equal(typeof body?.data?.refresh_token, "string");
  });
});
