/**
 * `/suvia` — the server-authoritative half of the app.
 *
 * Everything here exists because the client must not be able to talk its way to a different
 * answer: which reminder slots exist today, whether a challenge counts as met, how many snoozes
 * are left, and what the leaderboard shows. In v1 these were Postgres RPCs guarded by
 * `auth.uid()` plus two Deno edge functions. Directus has no `auth.uid()`, so the caller's id
 * comes from `req.accountability` — populated by Directus from the verified access token — and
 * is passed to the SQL functions as an argument. Nothing here reads a user id from a request
 * body, and nothing in `0002_functions.sql` should ever be reachable any other way.
 *
 * Photo verification is split into verify → resolve, exactly as in v1: verify returns a verdict
 * the app shows the user, and resolve is a separate call. Collapsing them would take away the
 * screen where a rejected photo is explained kindly and the user is invited to try again.
 *
 * The same reasoning is why entitlement is re-checked here. `RouteGate` and `SubscriptionGuard`
 * in the app compare RevenueCat's tier held in the app's own memory, which is a UI convenience
 * that can be wrong for a few seconds and is a lie outright in a tampered build. The two routes
 * that spend real money per call — `/verify-water-photo` (an Anthropic vision request plus a
 * `directus_files` upload) and `/leaderboard` — ask Postgres instead, through
 * `suvia_is_entitled()` (see `directus/migrations/0006_entitlement.sql`).
 */

import { timingSafeEqual } from "node:crypto";
import type { Request, Response, Router } from "express";

import { decodePhoto, PhotoError, UUID_RE, uploadPhoto } from "./files";
import { classifyWater, normalizeLocale } from "./vision";

/** Matches the check constraint on suvia_challenges.amount_ml. */
const MAX_AMOUNT_ML = 5000;

const T = {
  waterLogs: "suvia_water_logs",
  leaderboard: "suvia_leaderboard_daily",
};

/** Postgres `undefined_table`; knex re-throws the pg error, so `code` survives. */
const PG_UNDEFINED_TABLE = "42P01";
/** Postgres `unique_violation`. */
const PG_UNIQUE_VIOLATION = "23505";
/** Postgres `undefined_function`. */
const PG_UNDEFINED_FUNCTION = "42883";

function pgCode(error: unknown): unknown {
  return (error as { code?: unknown } | null | undefined)?.code;
}

/**
 * The leaderboard is the one route whose backing object can be absent while every collection the
 * app talks to is present: the view is created by `0003_views.sql`, applied by hand, and the
 * migrations are numbered precisely because they can be run partially. Left to `fail()` that
 * surfaced as a 500 whose only trace was a Postgres relation string in the server log.
 */
export function isMissingRelation(error: unknown): boolean {
  return pgCode(error) === PG_UNDEFINED_TABLE;
}

/** The `suvia_water_logs_photo_key` collision from two proofs racing on one photo (0005). */
export function isUniqueViolation(error: unknown): boolean {
  return pgCode(error) === PG_UNIQUE_VIOLATION;
}

/**
 * The entitlement predicate's own version of the leaderboard's missing view: `suvia_is_entitled`
 * is created by `0006_entitlement.sql`, and until that file is applied every paid route would
 * answer 500 with a Postgres function signature in the log. It must not fall back to "entitled" —
 * and it must not answer 402 either, because telling a paying user to pay for a migration nobody
 * ran sends them to the store instead of sending the operator to the file.
 */
export function isMissingFunction(error: unknown): boolean {
  return pgCode(error) === PG_UNDEFINED_FUNCTION;
}

// ── entitlement ───────────────────────────────────────────────────────────────────────────────

export type SubscriptionTier = "free" | "premium" | "vip";

/**
 * The same ranking as `TIER_LEVEL` in `clients/app/src/types/subscription.ts` and as
 * `public.suvia_tier_level()` in 0006, deliberately. Three copies is two too many, but the three
 * live in three languages; a disagreement about whether `vip` outranks `premium` shows up as a
 * paying user being refused by a route the app already let them into.
 */
const TIER_LEVEL: Record<SubscriptionTier, number> = { free: 0, premium: 1, vip: 2 };

/** RevenueCat entitlement id → tier. `free` is the absence of an entitlement, never an id. */
const TIER_BY_ENTITLEMENT: Record<string, SubscriptionTier> = { premium: "premium", vip: "vip" };

/**
 * The highest tier a webhook event's `entitlement_ids` grants, or `free` if it grants none we know.
 *
 * A subscriber can hold several entitlements at once (an upgrade mid-period, a promo granted on
 * top of a purchase). Taking the highest rather than the first means the order RevenueCat happens
 * to serialise the array in cannot decide what a user gets.
 */
export function highestTier(entitlementIds: unknown): SubscriptionTier {
  if (!Array.isArray(entitlementIds)) return "free";
  let best: SubscriptionTier = "free";
  for (const id of entitlementIds) {
    const tier = TIER_BY_ENTITLEMENT[String(id)];
    if (tier && TIER_LEVEL[tier] > TIER_LEVEL[best]) best = tier;
  }
  return best;
}

/**
 * The RevenueCat event types that re-assert an entitlement, and the one that removes it.
 *
 * `CANCELLATION` and `BILLING_ISSUE` are in neither set on purpose, and that is the load-bearing
 * decision in this file: a cancelled auto-renew is still entitled until the period it was paid for
 * ends, and a billing issue is RevenueCat's own grace period. Downgrading on either would take
 * premium away from someone who is still owed it. Only `EXPIRATION` downgrades, and if that event
 * is dropped or delayed the expiry timestamp already stored ends the entitlement on its own — see
 * the self-healing half of `suvia_is_entitled()`.
 *
 * `UNCANCELLATION`, `SUBSCRIBER_ALIAS` and `SUBSCRIPTION_PAUSED` are acknowledged and ignored, and
 * that is safe precisely because `CANCELLATION` never wrote anything: there is no state for an
 * `UNCANCELLATION` to undo, and the next `RENEWAL` re-asserts the truth regardless.
 *
 * `NON_RENEWING_PURCHASE` grants, and it has to: that is the event a **lifetime** purchase sends,
 * and the paywall sells one (`planName` has a `LIFETIME` case). The "a later RENEWAL re-asserts the
 * truth" argument that makes ignoring an event safe does not apply to it at all — a non-renewing
 * purchase never renews, so ignoring it meant the one customer who paid the most got nothing, for
 * good. It carries no `expiration_at_ms`, which is the right value for it: `suvia_is_entitled()`
 * reads a null expiry as "does not expire".
 *
 * `TRANSFER` is handled separately below, not listed here — its payload names
 * `transferred_from`/`transferred_to` instead of a single `app_user_id`, so it cannot go through the
 * same path.
 */
const GRANT_EVENTS = new Set([
  "INITIAL_PURCHASE",
  "TRIAL_STARTED",
  "RENEWAL",
  "PRODUCT_CHANGE",
  "NON_RENEWING_PURCHASE",
]);
const EXPIRE_EVENTS = new Set(["EXPIRATION"]);

/** RevenueCat sends every timestamp as epoch milliseconds. */
function msToDate(value: unknown): Date | null {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? new Date(value) : null;
}

/**
 * The two calls that cost money or leave a file behind, injectable so a test can prove the
 * entitlement gate runs *before* them.
 *
 * "The gate is in the right place" is the only property of this file worth testing and the only
 * one that cannot be tested by reading a response body: a free caller and a premium caller both
 * get a defensible-looking answer, and the difference between them is an Anthropic invoice.
 * Directus calls the endpoint with `(router, context)`, so nothing in production passes a third
 * argument.
 */
export interface EndpointDeps {
  classifyWater: typeof classifyWater;
  uploadPhoto: typeof uploadPhoto;
}

const REAL_DEPS: EndpointDeps = { classifyWater, uploadPhoto };

export default (router: Router, context: any, deps: EndpointDeps = REAL_DEPS) => {
  const { services, getSchema, database, env, logger } = context;

  const anthropicKey = env.ANTHROPIC_API_KEY;
  if (!anthropicKey) {
    logger.warn("[suvia] ANTHROPIC_API_KEY is not set — photo verification will fail");
  }

  // Unlike the Anthropic key, an unset secret here must never mean accept-all: this route is the
  // one thing that can hand out premium, and it is reachable without a Directus session.
  const webhookSecret = env.REVENUECAT_WEBHOOK_SECRET;
  if (!webhookSecret) {
    logger.warn(
      "[suvia] REVENUECAT_WEBHOOK_SECRET is not set — POST /suvia/revenuecat-webhook will reject " +
        "every call, so subscriptions will not be mirrored into suvia_profiles",
    );
  }

  /** The caller's Directus id, or null. Never trust a body field for this. */
  function userId(req: Request): string | null {
    const id = (req as any).accountability?.user;
    return typeof id === "string" && UUID_RE.test(id) ? id : null;
  }

  /**
   * One error shape for everything. `detail` is only populated for deliberate 4xx responses —
   * an unexpected failure returns a bare message, because Anthropic and Directus error text can
   * carry request context that has no business reaching a phone.
   */
  function fail(res: Response, error: unknown, where: string) {
    if (error instanceof PhotoError) {
      return res.status(error.status).json({ errors: [{ message: error.message }] });
    }
    logger.error(`[suvia] ${where}: ${(error as Error)?.message ?? error}`);
    return res.status(500).json({ errors: [{ message: "Internal error" }] });
  }

  function unauthorized(res: Response) {
    return res.status(401).json({ errors: [{ message: "Unauthorized" }] });
  }

  /**
   * 402, and a code the app can branch on.
   *
   * The code lives under `extensions` to match Directus's own error convention
   * (`errors[].extensions.code`) rather than inventing a shape — `SuviaApiError` in the app reads
   * it from there. Branching on the status alone would work today and stop working the moment a
   * second reason to answer 402 exists; branching on the message would break on translation.
   */
  function premiumRequired(res: Response) {
    return res.status(402).json({
      errors: [{ message: "Premium required", extensions: { code: "PREMIUM_REQUIRED" } }],
    });
  }

  /**
   * Asks the database whether this account may use a feature that costs us money. Returns true
   * when the caller may proceed; every other outcome has already been answered on `res`.
   *
   * The predicate itself is `public.suvia_is_entitled(uuid)` and is not restated here.
   */
  async function requireEntitled(res: Response, user: string, where: string): Promise<boolean> {
    try {
      const { rows } = await database.raw("select public.suvia_is_entitled(?) as entitled", [user]);
      if (rows[0]?.entitled === true) return true;
      premiumRequired(res);
      return false;
    } catch (error) {
      if (isMissingFunction(error)) {
        logger.error(
          `[suvia] ${where}: public.suvia_is_entitled does not exist — apply directus/migrations/0006_entitlement.sql`,
        );
        res.status(503).json({
          errors: [
            {
              message:
                "Entitlement cannot be checked: the suvia_is_entitled function is missing. Apply directus/migrations/0006_entitlement.sql.",
            },
          ],
        });
        return false;
      }
      fail(res, error, where);
      return false;
    }
  }

  /**
   * Constant-time comparison of the webhook's shared secret.
   *
   * `timingSafeEqual` throws on a length mismatch, so the length is compared first and is
   * therefore leaked — that is fine and unavoidable here: the secret's length is not the secret,
   * and an attacker who can measure it still has to guess every byte. A `===` would leak the
   * matching prefix, and this secret is the only thing standing between anyone on the internet
   * and a free premium grant.
   */
  function secretMatches(presented: unknown): boolean {
    if (!webhookSecret || typeof presented !== "string" || presented.length === 0) return false;
    const a = Buffer.from(presented, "utf8");
    const b = Buffer.from(String(webhookSecret), "utf8");
    return a.length === b.length && timingSafeEqual(a, b);
  }

  /** The verdict this extension stored on a file when it verified the photo. */
  function readVerdict(
    description: unknown,
  ): { is_water?: boolean; confidence?: number; reason?: string } | null {
    if (typeof description !== "string" || !description) return null;
    try {
      const parsed = JSON.parse(description);
      return parsed && typeof parsed === "object" ? parsed : null;
    } catch {
      return null;
    }
  }

  // ── planning ──────────────────────────────────────────────────────────────────────────────
  // Both are idempotent per local day: a second call the same day returns 0. The app calls them
  // on launch and on foreground, so they run far more often than they do anything.

  router.post("/plan-day", async (req: Request, res: Response) => {
    const user = userId(req);
    if (!user) return unauthorized(res);
    try {
      // `fresh_start` is only ever true for the plan that runs the moment onboarding ends — it
      // clears today's stale pending slots and plans future ones only, so nobody is locked out by
      // a window that opened before they finished signing up. See migration 0007.
      const { rows } = await database.raw("select public.suvia_plan_day(?, ?, ?) as count", [
        user,
        String(req.body?.tz ?? "UTC"),
        req.body?.fresh_start === true,
      ]);
      return res.json({ data: { count: Number(rows[0]?.count ?? 0) } });
    } catch (error) {
      return fail(res, error, "plan-day");
    }
  });

  // ── challenge transitions ─────────────────────────────────────────────────────────────────

  router.post("/challenges/:id/snooze", async (req: Request, res: Response) => {
    const user = userId(req);
    if (!user) return unauthorized(res);
    const challengeId = String(req.params.id ?? "");
    if (!UUID_RE.test(challengeId)) {
      return res.status(400).json({ errors: [{ message: "Invalid challenge id" }] });
    }
    try {
      const { rows } = await database.raw("select public.suvia_snooze_challenge(?, ?) as snoozed", [
        user,
        challengeId,
      ]);
      // false means the budget is spent or the challenge is not the caller's — both are a
      // normal answer ("the lock stays"), not an error.
      return res.json({ data: { snoozed: rows[0]?.snoozed === true } });
    } catch (error) {
      return fail(res, error, "snooze");
    }
  });

  router.post("/challenges/:id/resolve", async (req: Request, res: Response) => {
    const user = userId(req);
    if (!user) return unauthorized(res);
    const challengeId = String(req.params.id ?? "");
    if (!UUID_RE.test(challengeId)) {
      return res.status(400).json({ errors: [{ message: "Invalid challenge id" }] });
    }
    /**
     * Gated for the same reason `/verify-water-photo` is, and the gate there is not enough on its
     * own: `photo` is optional here, so a caller who never asks for a vision check can still resolve
     * a challenge and take the credit, the points and the lock release. Gating only the expensive
     * endpoint would have left the premium *outcome* free and merely made the AI part of it optional.
     */
    if (!(await requireEntitled(res, user, "challenges/resolve"))) return;
    const { photo, confidence, reason, amount_ml } = req.body ?? {};
    if (!Number.isInteger(amount_ml) || amount_ml <= 0 || amount_ml > 5000) {
      return res.status(400).json({ errors: [{ message: "Invalid amount_ml" }] });
    }
    try {
      const { rows } = await database.raw(
        "select public.suvia_resolve_challenge(?, ?, ?, ?, ?, ?) as resolved",
        [
          user,
          challengeId,
          photo && UUID_RE.test(String(photo)) ? photo : null,
          typeof confidence === "number" ? confidence : null,
          typeof reason === "string" ? reason : null,
          amount_ml,
        ],
      );
      return res.json({ data: { resolved: rows[0]?.resolved === true } });
    } catch (error) {
      return fail(res, error, "resolve-challenge");
    }
  });

  // ── photo verification ────────────────────────────────────────────────────────────────────

  router.post("/verify-water-photo", async (req: Request, res: Response) => {
    const user = userId(req);
    if (!user) return unauthorized(res);
    // Before decoding, before the upload, before the vision call. This route is the one that spends
    // money per request — an Anthropic vision call plus a file that then has to be stored and
    // purged — so a gated caller must cost nothing at all. Anywhere further down and the invoice
    // arrives whether or not the user was allowed.
    if (!(await requireEntitled(res, user, "verify-water-photo"))) return;
    try {
      const buffer = decodePhoto(req.body?.photo_base64);
      const locale = normalizeLocale(req.body?.locale);
      const schema = await getSchema();
      const accountability = (req as any).accountability;

      // Uploaded before the verdict, deliberately: the photo is the evidence for the verdict,
      // so a rejected attempt is still stored and still purged 24h later.
      const photo = await deps.uploadPhoto({
        services,
        schema,
        knex: database,
        accountability,
        env,
        buffer,
        filename: `water-${user}-${Date.now()}.jpg`,
      });

      const verdict = await deps.classifyWater(anthropicKey, buffer.toString("base64"), locale);

      // Recorded on the file itself, so POST /water-logs can confirm later that this photo was
      // accepted without trusting the client to say so. The client can create files but not
      // update them, which is what makes this trustworthy rather than decorative.
      await database("directus_files")
        .where({ id: photo })
        .update({ description: JSON.stringify(verdict) });

      return res.json({ data: { ...verdict, photo } });
    } catch (error) {
      return fail(res, error, "verify-water-photo");
    }
  });

  // ── voluntary water logs ──────────────────────────────────────────────────────────────────
  //
  // The client may only create MANUAL water logs; a photo-backed, ai_verified row is evidence
  // and evidence the client can write is evidence it can forge. On the challenge path the row
  // is written by suvia_resolve_challenge. This is the other path: the user tapped "+" of their
  // own accord, photographed a drink, and it passed — there is no challenge to resolve, but the
  // log should still say it was verified.
  //
  // The verdict is not taken from the request. It is read back off the file record, where
  // /verify-water-photo stored it at upload time, and the client has no permission to update a
  // file — so a rejected photo cannot be replayed here as an accepted one.

  router.post("/water-logs", async (req: Request, res: Response) => {
    const user = userId(req);
    if (!user) return unauthorized(res);

    const { photo, amount_ml } = req.body ?? {};
    if (!photo || !UUID_RE.test(String(photo))) {
      return res.status(400).json({ errors: [{ message: "Invalid photo id" }] });
    }
    if (!Number.isInteger(amount_ml) || amount_ml <= 0 || amount_ml > MAX_AMOUNT_ML) {
      return res.status(400).json({ errors: [{ message: "Invalid amount_ml" }] });
    }

    try {
      const file = await database("directus_files")
        .where({ id: photo, uploaded_by: user })
        .first("id", "description");
      if (!file) {
        return res.status(404).json({ errors: [{ message: "Photo not found" }] });
      }

      const verdict = readVerdict(file.description);
      if (!verdict?.is_water) {
        return res.status(409).json({ errors: [{ message: "Photo was not verified as water" }] });
      }

      // One log per photo, and the same answer however many times the request arrives.
      //
      // A verified photo stays replayable for the 24 hours before the purge deletes it, and
      // nothing about this route made a second call with the same id inert: it inserted another
      // verified row. That was already an inflated daily total; since 0005 it is also ten points
      // per call, minted in a loop. The unique index in 0005 is what actually forbids it — this
      // returns the log the caller already has instead of the 500 the collision would otherwise
      // produce, so a retry after a lost response, or a double-tapped "+", still reads as success.
      const already = await database(T.waterLogs).where({ user, photo }).first("id");
      if (already) {
        return res.json({ data: { id: already.id } });
      }

      let row: { id?: string } | undefined;
      try {
        [row] = await database(T.waterLogs)
          .insert({
            id: database.raw("gen_random_uuid()"),
            user,
            amount_ml,
            source: "photo",
            photo,
            ai_verified: true,
            ai_confidence: verdict.confidence ?? null,
            ai_reason: verdict.reason ?? null,
          })
          .returning("id");
      } catch (error) {
        if (!isUniqueViolation(error)) throw error;
        const raced = await database(T.waterLogs).where({ user, photo }).first("id");
        return res.json({ data: { id: raced?.id ?? null } });
      }

      return res.json({ data: { id: row?.id ?? null } });
    } catch (error) {
      return fail(res, error, "water-logs");
    }
  });

  // ── leaderboard ───────────────────────────────────────────────────────────────────────────
  // Served here rather than as a Directus collection so the only columns that can ever leave
  // the database are the ones this query names. The view is already bounded to a three-day
  // window and 600 rows (see 0003_views.sql).

  router.get("/leaderboard", async (req: Request, res: Response) => {
    const user = userId(req);
    if (!user) return unauthorized(res);
    // Premium (product decision). Note what this does NOT do: the view still ranks everybody, so a
    // free user keeps appearing on other people's boards and only loses the ability to see it.
    // Premium-only competition would be a change to 0003_views.sql, not to this line.
    if (!(await requireEntitled(res, user, "leaderboard"))) return;
    const day = String(req.query.day ?? "");
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) {
      return res.status(400).json({ errors: [{ message: "day must be YYYY-MM-DD" }] });
    }
    try {
      const rows = await database(T.leaderboard)
        .where({ day })
        .orderBy("rank", "asc")
        .limit(100)
        .select("day", "user", "display_name", "total_ml", "goal_ml", "completed", "rank");
      return res.json({ data: rows });
    } catch (error) {
      // 503, not 500: the instance is missing a migration, so this is a deployment state that
      // will fix itself the moment 0003 is applied — and the message says which file, because
      // the person reading it is whoever deployed. The app renders its own copy for a failed
      // leaderboard, so nothing here reaches a user.
      if (isMissingRelation(error)) {
        logger.error(
          `[suvia] leaderboard: relation ${T.leaderboard} does not exist — apply directus/migrations/0003_views.sql`,
        );
        return res.status(503).json({
          errors: [
            {
              message:
                "Leaderboard is unavailable: the suvia_leaderboard_daily view is missing. Apply directus/migrations/0003_views.sql.",
            },
          ],
        });
      }
      return fail(res, error, "leaderboard");
    }
  });

  // ── subscriptions ─────────────────────────────────────────────────────────────────────────
  //
  // The only route in this extension that is NOT authenticated by `req.accountability`: RevenueCat
  // calls it server-to-server and has no Directus session, so a static shared secret is the only
  // thing available. Everything it writes is a mirror of RevenueCat's own state — nothing here is
  // a source of truth, which is why a lost event is survivable and a *misordered* one is not.
  //
  // `app_user_id` is the Directus user id, without a lookup table: `identifyUser()` in
  // clients/app/src/stores/subscription-store.ts passes it straight to `Purchases.logIn()`.

  router.post("/revenuecat-webhook", async (req: Request, res: Response) => {
    // Checked before the body is looked at, and before any query runs. An unauthenticated caller
    // must not be able to make this route do work, and must not learn anything from it either.
    const presented = (req.headers as Record<string, unknown> | undefined)?.authorization;
    if (!secretMatches(presented)) {
      logger.warn(
        "[suvia] revenuecat-webhook: rejected a call with a missing or incorrect Authorization header",
      );
      return res.status(401).json({
        errors: [{ message: "Unauthorized", extensions: { code: "WEBHOOK_UNAUTHORIZED" } }],
      });
    }

    const event = (req.body as any)?.event;
    const type = typeof event?.type === "string" ? event.type : "";
    const appUserId = typeof event?.app_user_id === "string" ? event.app_user_id : "";
    const eventAt = msToDate(event?.event_timestamp_ms);

    /**
     * A subscription moving between accounts.
     *
     * Its own branch because its payload has no `app_user_id` at all: it names
     * `transferred_from` and `transferred_to` (arrays — a transfer can involve aliases of the same
     * subscriber), so every check below this point would read undefined and the event would fall out
     * as unapplicable. Ignoring it left the receiving account un-entitled until its next RENEWAL,
     * which is a year for the annual plan, and left the giving account entitled on a subscription it
     * no longer has.
     *
     * Both sides are written from the entitlement RevenueCat reports on the event, and both carry
     * the same staleness guard as everything else. The giving side is expired rather than deleted
     * so the subscription audit fields remain available.
     */
    if (type === "TRANSFER" && eventAt) {
      const ids = (value: unknown): string[] =>
        Array.isArray(value) ? value.filter((v) => typeof v === "string" && UUID_RE.test(v)) : [];
      const to = ids(event?.transferred_to);
      const from = ids(event?.transferred_from);

      if (to.length === 0 && from.length === 0) {
        logger.warn(
          `[suvia] revenuecat-webhook: TRANSFER names no Directus user on either side — transferred_to=${JSON.stringify(event?.transferred_to)} transferred_from=${JSON.stringify(event?.transferred_from)}`,
        );
        return res.json({ data: { received: true, matched: false } });
      }

      try {
        const gainedTier = highestTier(event?.entitlement_ids);
        let matched = 0;

        for (const [users, tierForSide] of [
          [to, gainedTier],
          [from, "free" as const],
        ] as const) {
          if (users.length === 0) continue;
          // `tierForSide === "free"` is the losing side and needs no expiry written: the tier alone
          // ends the entitlement. An unmapped entitlement id on the gaining side is the same
          // configuration bug the grant path refuses to act on, so it is refused here too.
          if (tierForSide !== "free" && gainedTier === "free") {
            logger.error(
              `[suvia] revenuecat-webhook: TRANSFER carries no entitlement this server maps (${JSON.stringify(event?.entitlement_ids)}) — not granting`,
            );
            continue;
          }
          const { rows } = await database.raw(
            `update public.suvia_profiles
                set subscription_tier = ?,
                    subscription_expires_at = coalesce(?, subscription_expires_at),
                    subscription_event_at = ?
              where "user" = any(?)
                and (subscription_event_at is null or subscription_event_at <= ?)
            returning "user"`,
            [
              tierForSide,
              tierForSide === "free" ? null : msToDate(event?.expiration_at_ms),
              eventAt,
              users,
              eventAt,
            ],
          );
          matched += rows.length;
        }

        logger.info(
          `[suvia] revenuecat-webhook: TRANSFER applied to ${matched} row(s) — to=${to.length} from=${from.length} tier=${gainedTier}`,
        );
        return res.json({ data: { received: true, matched: matched > 0 } });
      } catch (error) {
        return fail(res, error, "revenuecat-webhook");
      }
    }

    // 200 for every one of these, not 400: RevenueCat retries any non-2xx, forever, and no retry
    // turns a malformed envelope into a well-formed one. `app_user_id` failing UUID_RE is the
    // ordinary case of a purchase made before login, where RevenueCat's id is still
    // `$RCAnonymousID:…` and there is no Directus user to attribute it to yet.
    if (!type || !eventAt || !UUID_RE.test(appUserId)) {
      logger.warn(
        `[suvia] revenuecat-webhook: ignoring an event this route cannot apply (type=${type || "?"}, app_user_id=${appUserId || "?"}, event_timestamp_ms=${String(event?.event_timestamp_ms)})`,
      );
      return res.json({ data: { received: true, matched: false } });
    }

    if (!GRANT_EVENTS.has(type) && !EXPIRE_EVENTS.has(type)) {
      // CANCELLATION and BILLING_ISSUE arrive here and are supposed to: see GRANT_EVENTS.
      logger.info(`[suvia] revenuecat-webhook: ${type} needs no change to the stored entitlement`);
      return res.json({ data: { received: true, matched: false } });
    }

    const tier = EXPIRE_EVENTS.has(type) ? "free" : highestTier(event.entitlement_ids);
    if (tier === "free" && !EXPIRE_EVENTS.has(type)) {
      // A purchase whose entitlement id is not one this server knows. Writing what it mapped to
      // would downgrade a user who just paid, so it writes nothing and says so loudly: this is a
      // RevenueCat dashboard/`TIER_BY_ENTITLEMENT` mismatch, and it is a configuration bug.
      logger.error(
        `[suvia] revenuecat-webhook: ${type} for ${appUserId} carries no entitlement this server maps (${JSON.stringify(event.entitlement_ids)}) — ignoring rather than downgrading`,
      );
      return res.json({ data: { received: true, matched: false } });
    }

    try {
      // One statement, and the ordering guard is in its WHERE clause.
      //
      // Delivery is at-least-once and NOT ordered. Without the guard, a delayed CANCELLATION-era
      // EXPIRATION arriving after a newer RENEWAL would regress a paying user to free. With it, a
      // stale event simply matches no row — a no-op rather than an error, because an error would
      // have RevenueCat redeliver the same stale event forever.
      //
      // `<=` rather than `<` so a redelivery of the event that is already stored re-applies the
      // same values: that is what makes a retry idempotent instead of merely harmless.
      //
      // `coalesce(?, column)` twice, so an event that does not carry a period end or a
      // subscriber id does not erase the one already stored.
      const { rows } = await database.raw(
        `update public.suvia_profiles
            set subscription_tier = ?,
                subscription_expires_at = coalesce(?, subscription_expires_at),
                subscription_event_at = ?,
                revenuecat_id = coalesce(?, revenuecat_id)
          where "user" = ?
            and (subscription_event_at is null or subscription_event_at <= ?)
        returning "user"`,
        [
          tier,
          msToDate(event.expiration_at_ms),
          eventAt,
          typeof event.original_app_user_id === "string" ? event.original_app_user_id : null,
          appUserId,
          eventAt,
        ],
      );

      if (rows.length > 0) {
        logger.info(
          `[suvia] revenuecat-webhook: ${type} applied for ${appUserId} — tier=${tier} (${event.environment ?? "unknown"})`,
        );
        return res.json({ data: { received: true, matched: true } });
      }

      // Zero rows has two causes and they need different people: a user this instance has never
      // seen, or an event older than the one already applied. Costs one extra read on a path that
      // should be rare, and turns an ambiguous silence into a log line somebody can act on.
      const { rows: existing } = await database.raw(
        'select 1 as ok from public.suvia_profiles where "user" = ?',
        [appUserId],
      );
      if (existing.length === 0) {
        // A grant for a user whose profile row does not exist YET. Not a lost cause and not
        // droppable: the row is written by the client's onboarding flush, the paywall is shown in
        // the same few seconds, and a purchase can easily land first — or the flush can have failed
        // and be waiting on its retry. Dropping the event left someone who had just paid reading as
        // `free` to every server-side gate until their next RENEWAL, which for an annual plan is a
        // year away and for a lifetime purchase is never.
        //
        // So the row is created carrying the entitlement. Every other column has a default (see
        // `directus/schema/suvia-schema.mjs`) so `user` is the only value needed, and the client's
        // own `loadProfile` fills the rest in when it next runs — it updates the row it finds rather
        // than replacing it. `on conflict` is not decoration: the flush may commit between the read
        // above and this insert.
        //
        // Expiries only downgrade an existing row. A profile invented to record an EXPIRATION would
        // assert "this user is not entitled" about someone this instance has never seen, and the
        // absence of a row already says that.
        if (EXPIRE_EVENTS.has(type)) {
          logger.warn(
            `[suvia] revenuecat-webhook: no suvia_profiles row for app_user_id ${appUserId} — ${type} needs none`,
          );
          return res.json({ data: { received: true, matched: false } });
        }

        const { rows: created } = await database.raw(
          `insert into public.suvia_profiles
             ("user", subscription_tier, subscription_expires_at, subscription_event_at, revenuecat_id)
           values (?, ?, ?, ?, ?)
           on conflict ("user") do update
             set subscription_tier = excluded.subscription_tier,
                 subscription_expires_at =
                   coalesce(excluded.subscription_expires_at, public.suvia_profiles.subscription_expires_at),
                 subscription_event_at = excluded.subscription_event_at,
                 revenuecat_id = coalesce(excluded.revenuecat_id, public.suvia_profiles.revenuecat_id)
           where public.suvia_profiles.subscription_event_at is null
              or public.suvia_profiles.subscription_event_at <= excluded.subscription_event_at
        returning "user"`,
          [
            appUserId,
            tier,
            msToDate(event.expiration_at_ms),
            eventAt,
            typeof event.original_app_user_id === "string" ? event.original_app_user_id : null,
          ],
        );

        if (created.length > 0) {
          logger.info(
            `[suvia] revenuecat-webhook: ${type} applied for ${appUserId} by creating its profile row — tier=${tier} (${event.environment ?? "unknown"})`,
          );
          return res.json({ data: { received: true, matched: true } });
        }

        logger.info(
          `[suvia] revenuecat-webhook: ${type} for ${appUserId} lost the race to a newer event — ignored`,
        );
        return res.json({ data: { received: true, matched: false } });
      }
      // The row exists (the branch above returned for every case where it did not), so zero updated
      // rows can only mean the guard rejected this event as stale.
      logger.info(
        `[suvia] revenuecat-webhook: ${type} for ${appUserId} is older than the event already applied — ignored`,
      );
      return res.json({ data: { received: true, matched: false } });
    } catch (error) {
      // 500 here is correct: a transient database failure IS something a RevenueCat retry fixes.
      return fail(res, error, "revenuecat-webhook");
    }
  });
};
