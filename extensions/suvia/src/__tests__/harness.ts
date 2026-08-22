/**
 * A router, a request, a response and just enough of Postgres to run one route.
 *
 * `endpoint.test.ts` says "pure functions only", and for what it covers that is right. The
 * entitlement work cannot be covered that way: its whole content is *where* a check sits relative
 * to an Anthropic call, and whether a second delivery of the same webhook changes a row. Neither is
 * visible in a return value.
 *
 * So this is a harness, not a mock framework: no express, no knex, no database, no dependency. The
 * fakes are small enough to read in one sitting, and the parts that stand in for SQL do only what
 * the statements in `endpoint.ts` actually ask for.
 *
 * What this can and cannot prove:
 *
 * - It CAN prove the route asks the right question, in the right order, and honours the answer —
 *   that a free caller never reaches the vision call, that a stale webhook event matches no row,
 *   that a replayed claim returns the grant it already had.
 * - It CANNOT prove `suvia_is_entitled()` or the write-once trigger are correct; those are SQL and
 *   are verified by hand against a real database (`directus/README.md`, verification steps 8–11).
 *   `fakeProfiles` mirrors their behaviour deliberately so a disagreement between the two is a
 *   thing a human has to notice — which is exactly why the mirror is kept to a few lines.
 */

import type { Request, Response, Router } from "express";

import createEndpoint from "../endpoint";

// ── request / response ──────────────────────────────────────────────────────────────────────

export interface FakeResponse {
  statusCode: number;
  body: any;
}

export function fakeResponse(): FakeResponse & Response {
  const res: any = { statusCode: 200, body: undefined };
  res.status = (code: number) => {
    res.statusCode = code;
    return res;
  };
  res.json = (body: unknown) => {
    res.body = body;
    return res;
  };
  return res;
}

export interface FakeRequestInit {
  user?: string | null;
  body?: unknown;
  query?: Record<string, unknown>;
  params?: Record<string, unknown>;
  headers?: Record<string, string>;
}

export function fakeRequest(init: FakeRequestInit = {}): Request {
  return {
    // Directus populates this from the verified access token. `undefined` is an unauthenticated
    // call; the routes must not read a user id from anywhere else.
    accountability: init.user === undefined ? undefined : { user: init.user },
    body: init.body,
    query: init.query ?? {},
    params: init.params ?? {},
    // Node lowercases incoming header names, so this is what express hands a handler.
    headers: init.headers ?? {},
  } as unknown as Request;
}

// ── the database ────────────────────────────────────────────────────────────────────────────

export interface RawCall {
  sql: string;
  bindings: unknown[];
}

export type RawProgram = (sql: string, bindings: unknown[]) => unknown;

export interface FakeDatabase {
  (table: string): any;
  raw(sql: string, bindings?: unknown[]): Promise<unknown>;
  rawCalls: RawCall[];
  tableCalls: string[];
}

/**
 * `database.raw(...)` answered by `program`, and `database(table)` answered by `tables`.
 *
 * A table that is not in `tables` throws, and that is load-bearing rather than lazy: the point of
 * the gate is that a rejected caller touches nothing, so "this route queried something it should
 * not have" has to be a test failure and not a silently empty result.
 */
export function fakeDatabase(program: RawProgram, tables: Record<string, unknown> = {}) {
  const rawCalls: RawCall[] = [];
  const tableCalls: string[] = [];

  const db: any = (table: string) => {
    tableCalls.push(table);
    if (!(table in tables)) {
      throw new Error(`fakeDatabase: unexpected query against ${table}`);
    }
    const result = tables[table];
    // Every chained call returns the same builder; awaiting it yields the programmed result. The
    // routes only ever build one chain per table, so nothing needs per-method behaviour.
    const builder: any = new Proxy(
      {},
      {
        get(_target, prop) {
          if (prop === "then") {
            return (resolve: (v: unknown) => unknown, reject: (e: unknown) => unknown) =>
              Promise.resolve(result).then(resolve, reject);
          }
          if (typeof prop !== "string") return undefined;
          return () => builder;
        },
      },
    );
    return builder;
  };

  db.raw = async (sql: string, bindings: unknown[] = []) => {
    rawCalls.push({ sql, bindings });
    return program(sql, bindings);
  };
  db.rawCalls = rawCalls;
  db.tableCalls = tableCalls;
  return db as FakeDatabase;
}

// ── suvia_profiles ──────────────────────────────────────────────────────────────────────────

export type Tier = "free" | "premium" | "vip";

export interface FakeProfile {
  user: string;
  subscription_tier: Tier;
  subscription_expires_at: Date | null;
  subscription_event_at: Date | null;
  revenuecat_id: string | null;
}

export function fakeProfile(user: string, over: Partial<FakeProfile> = {}): FakeProfile {
  return {
    user,
    subscription_tier: "free",
    subscription_expires_at: null,
    subscription_event_at: null,
    revenuecat_id: null,
    ...over,
  };
}

const TIER_RANK: Record<Tier, number> = { free: 0, premium: 1, vip: 2 };

/**
 * The statements `endpoint.ts` sends to `suvia_profiles`, run over a Map.
 *
 * The entitlement predicate and webhook ordering guard mirrored from 0006 are each one expression
 * here, so they can be compared to the
 * SQL by eye. An unrecognised statement throws rather than returning an empty result: a route that
 * starts asking a different question should fail here, not pass by accident.
 */
export function fakeProfiles(rows: FakeProfile[], now: () => Date = () => new Date()) {
  const byUser = new Map<string, FakeProfile>(rows.map((row) => [row.user, row]));

  const program: RawProgram = (sql, bindings) => {
    const statement = sql.replace(/\s+/g, " ").trim().toLowerCase();

    // public.suvia_is_entitled(uuid)
    if (statement.includes("suvia_is_entitled")) {
      const profile = byUser.get(String(bindings[0]));
      const entitled =
        !!profile &&
        TIER_RANK[profile.subscription_tier] >= TIER_RANK.premium &&
        (profile.subscription_expires_at === null ||
          profile.subscription_expires_at.getTime() > now().getTime());
      return { rows: [{ entitled }] };
    }

    // TRANSFER's guarded update, which writes a whole side of the transfer at once. Matched BEFORE
    // the single-user update below: it also starts with `update public.suvia_profiles` and mentions
    // `subscription_tier =`, but it binds a user ARRAY and no revenuecat_id, so falling through
    // would destructure its bindings one position out and silently assert against nonsense.
    if (
      statement.startsWith("update public.suvia_profiles") &&
      statement.includes('"user" = any(')
    ) {
      const [tier, expires, eventAt, users, guardAt] = bindings as [
        Tier,
        Date | null,
        Date,
        string[],
        Date,
      ];
      const written: { user: string }[] = [];
      for (const user of users) {
        const profile = byUser.get(user);
        if (!profile) continue;
        if (
          profile.subscription_event_at !== null &&
          profile.subscription_event_at.getTime() > guardAt.getTime()
        ) {
          continue;
        }
        profile.subscription_tier = tier;
        if (expires !== null) profile.subscription_expires_at = expires;
        profile.subscription_event_at = eventAt;
        written.push({ user: profile.user });
      }
      return { rows: written };
    }

    // The webhook's upsert, for a grant that arrives before the client has written a profile row.
    if (statement.startsWith("insert into public.suvia_profiles")) {
      const [user, tier, expires, eventAt, revenuecatId] = bindings as [
        string,
        Tier,
        Date | null,
        Date,
        string | null,
      ];
      const existing = byUser.get(user);
      if (existing) {
        // `on conflict … do update … where` — the same staleness guard, expressed on the row that
        // was already there.
        if (
          existing.subscription_event_at !== null &&
          existing.subscription_event_at.getTime() > eventAt.getTime()
        ) {
          return { rows: [] };
        }
        existing.subscription_tier = tier;
        if (expires !== null) existing.subscription_expires_at = expires;
        existing.subscription_event_at = eventAt;
        if (revenuecatId !== null) existing.revenuecat_id = revenuecatId;
        return { rows: [{ user }] };
      }
      // Every other column has a database default, which is what makes this insert legal with only
      // the entitlement columns set.
      byUser.set(user, {
        ...fakeProfile(user),
        subscription_tier: tier,
        subscription_expires_at: expires,
        subscription_event_at: eventAt,
        revenuecat_id: revenuecatId,
      });
      return { rows: [{ user }] };
    }

    // The webhook's guarded update.
    if (
      statement.startsWith("update public.suvia_profiles") &&
      statement.includes("subscription_tier =")
    ) {
      const [tier, expires, eventAt, revenuecatId, user, guardAt] = bindings as [
        Tier,
        Date | null,
        Date,
        string | null,
        string,
        Date,
      ];
      const profile = byUser.get(user);
      if (!profile) return { rows: [] };
      // `and (subscription_event_at is null or subscription_event_at <= ?)`
      if (
        profile.subscription_event_at !== null &&
        profile.subscription_event_at.getTime() > guardAt.getTime()
      ) {
        return { rows: [] };
      }
      profile.subscription_tier = tier;
      if (expires !== null) profile.subscription_expires_at = expires;
      profile.subscription_event_at = eventAt;
      if (revenuecatId !== null) profile.revenuecat_id = revenuecatId;
      return { rows: [{ user: profile.user }] };
    }

    // The webhook's "does this user exist at all" read.
    if (statement.startsWith("select 1 as ok")) {
      return { rows: byUser.has(String(bindings[0])) ? [{ ok: 1 }] : [] };
    }

    throw new Error(`fakeProfiles: unprogrammed statement: ${statement}`);
  };

  return { byUser, program };
}

// ── the endpoint under test ─────────────────────────────────────────────────────────────────

export interface MountOptions {
  program?: RawProgram;
  tables?: Record<string, unknown>;
  env?: Record<string, string>;
}

export interface Harness {
  call(method: "POST" | "GET", path: string, req: Request): Promise<FakeResponse>;
  db: FakeDatabase;
  /** Every side effect the entitlement gate is supposed to prevent, counted. */
  spies: { vision: number; upload: number; schema: number };
  logs: { level: string; message: string }[];
}

export function mount(options: MountOptions = {}): Harness {
  const routes = new Map<string, (req: Request, res: Response) => unknown>();
  const router = {
    post: (path: string, handler: any) => routes.set(`POST ${path}`, handler),
    get: (path: string, handler: any) => routes.set(`GET ${path}`, handler),
  } as unknown as Router;

  const logs: { level: string; message: string }[] = [];
  const logger = {
    info: (message: string) => logs.push({ level: "info", message }),
    warn: (message: string) => logs.push({ level: "warn", message }),
    error: (message: string) => logs.push({ level: "error", message }),
  };

  const spies = { vision: 0, upload: 0, schema: 0 };
  const db = fakeDatabase(
    options.program ??
      (() => {
        throw new Error("mount: no raw program was provided");
      }),
    options.tables,
  );

  createEndpoint(
    router,
    {
      // Constructing a FilesService is a side effect the gate must prevent; `uploadPhoto` is a spy
      // here, so a route that reaches for the real service is a bug.
      services: {
        get FilesService() {
          throw new Error("harness: FilesService must not be constructed in these tests");
        },
      },
      getSchema: async () => {
        spies.schema += 1;
        return {};
      },
      database: db,
      env: options.env ?? {},
      logger,
    },
    {
      classifyWater: async () => {
        spies.vision += 1;
        return { is_water: true, confidence: 0.9, reason: "ok", model: "fake" };
      },
      uploadPhoto: async () => {
        spies.upload += 1;
        return "11111111-1111-4111-8111-111111111111";
      },
    },
  );

  return {
    async call(method, path, req) {
      const handler = routes.get(`${method} ${path}`);
      if (!handler) throw new Error(`harness: no route ${method} ${path}`);
      const res = fakeResponse();
      await handler(req, res);
      return res;
    },
    db,
    spies,
    logs,
  };
}
