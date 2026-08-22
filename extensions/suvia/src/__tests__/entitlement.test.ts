/**
 * `bun test src/__tests__` from `directus/extensions/suvia`.
 *
 * The gate in front of the paid routes and the RevenueCat webhook can both fail silently: a gate
 * in the wrong place still returns a valid-looking verdict, and a webhook that applies events in
 * arrival order still returns 200. These tests run the real
 * handlers over the harness in `harness.ts`; see its header for what that can and cannot prove.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { highestTier } from "../endpoint";
import { fakeProfile, fakeProfiles, fakeRequest, mount } from "./harness";

const USER = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OTHER = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const PHOTO_BASE64 = Buffer.from("not really a jpeg").toString("base64");
const SECRET = "s3cret-webhook-token";

const hour = 60 * 60 * 1000;

function verifyRequest() {
  return fakeRequest({ user: USER, body: { photo_base64: PHOTO_BASE64, locale: "tr" } });
}

// ── the gate ────────────────────────────────────────────────────────────────────────────────

describe("entitlement gate", () => {
  it("lets a premium subscriber through to the vision call", async () => {
    const { program } = fakeProfiles([
      fakeProfile(USER, {
        subscription_tier: "premium",
        subscription_expires_at: new Date(Date.now() + 24 * hour),
      }),
    ]);
    const harness = mount({ program, tables: { directus_files: 1 } });

    const res = await harness.call("POST", "/verify-water-photo", verifyRequest());

    assert.equal(res.statusCode, 200);
    assert.equal(res.body.data.is_water, true);
    assert.equal(harness.spies.vision, 1);
    assert.equal(harness.spies.upload, 1);
  });

  it("refuses a free user WITHOUT decoding, uploading or classifying anything", async () => {
    const { program } = fakeProfiles([fakeProfile(USER)]);
    const harness = mount({ program, tables: { directus_files: 1 } });

    const res = await harness.call("POST", "/verify-water-photo", verifyRequest());

    assert.equal(res.statusCode, 402);
    assert.equal(res.body.errors[0].extensions.code, "PREMIUM_REQUIRED");
    // The point of the whole exercise: a refused caller costs an Anthropic call of nothing, a file
    // of nothing, and a purge of nothing.
    assert.equal(harness.spies.vision, 0);
    assert.equal(harness.spies.upload, 0);
    assert.equal(harness.spies.schema, 0);
    assert.deepEqual(harness.db.tableCalls, []);
  });

  it("refuses a subscriber whose period has already ended, tier untouched", async () => {
    // The self-healing half: no EXPIRATION webhook has arrived (tier is still premium) and the
    // stored expiry is all it takes.
    const { program } = fakeProfiles([
      fakeProfile(USER, {
        subscription_tier: "premium",
        subscription_expires_at: new Date(Date.now() - hour),
      }),
    ]);
    const harness = mount({ program, tables: { directus_files: 1 } });

    const res = await harness.call("POST", "/verify-water-photo", verifyRequest());

    assert.equal(res.statusCode, 402);
    assert.equal(harness.spies.vision, 0);
  });

  it("fails closed for a caller with no profile row", async () => {
    const { program } = fakeProfiles([]);
    const harness = mount({ program, tables: { directus_files: 1 } });

    const res = await harness.call("POST", "/verify-water-photo", verifyRequest());

    assert.equal(res.statusCode, 402);
    assert.equal(harness.spies.vision, 0);
  });

  it("gates the leaderboard before reading the view", async () => {
    const { program } = fakeProfiles([fakeProfile(USER)]);
    const harness = mount({ program, tables: { suvia_leaderboard_daily: [] } });

    const res = await harness.call(
      "GET",
      "/leaderboard",
      fakeRequest({ user: USER, query: { day: "2026-08-18" } }),
    );

    assert.equal(res.statusCode, 402);
    assert.deepEqual(harness.db.tableCalls, []);
  });

  it("serves the leaderboard to a vip", async () => {
    const row = { day: "2026-08-18", user: USER, display_name: "A", total_ml: 1, rank: 1 };
    const { program } = fakeProfiles([fakeProfile(USER, { subscription_tier: "vip" })]);
    const harness = mount({ program, tables: { suvia_leaderboard_daily: [row] } });

    const res = await harness.call(
      "GET",
      "/leaderboard",
      fakeRequest({ user: USER, query: { day: "2026-08-18" } }),
    );

    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body.data, [row]);
  });

  it("answers 401 before asking the database anything", async () => {
    const harness = mount({
      program: () => {
        throw new Error("must not be reached");
      },
    });

    const res = await harness.call("POST", "/verify-water-photo", fakeRequest({ user: null }));

    assert.equal(res.statusCode, 401);
    assert.deepEqual(harness.db.rawCalls, []);
  });

  it("answers 503 naming 0006 when suvia_is_entitled does not exist yet", async () => {
    // Not 402: telling a paying user to pay because nobody ran a migration sends them to the store
    // instead of sending the operator to the file.
    const harness = mount({
      program: () => {
        throw Object.assign(new Error("function public.suvia_is_entitled(uuid) does not exist"), {
          code: "42883",
        });
      },
    });

    const res = await harness.call("POST", "/verify-water-photo", verifyRequest());

    assert.equal(res.statusCode, 503);
    assert.match(res.body.errors[0].message, /0006_entitlement\.sql/);
    assert.equal(harness.spies.vision, 0);
  });
});

// ── the webhook ─────────────────────────────────────────────────────────────────────────────

function webhookRequest(event: Record<string, unknown>, secret: string | null = SECRET) {
  return fakeRequest({
    body: { api_version: "1.0", event },
    headers: secret === null ? {} : { authorization: secret },
  });
}

function grant(over: Record<string, unknown> = {}) {
  return {
    id: "evt-1",
    type: "RENEWAL",
    app_user_id: USER,
    entitlement_ids: ["premium"],
    period_type: "NORMAL",
    environment: "PRODUCTION",
    expiration_at_ms: Date.now() + 30 * 24 * hour,
    event_timestamp_ms: Date.now(),
    ...over,
  };
}

describe("revenuecat webhook auth", () => {
  it("rejects every call when the secret is not configured", async () => {
    const harness = mount({
      program: () => {
        throw new Error("must not be reached");
      },
      env: {},
    });

    const res = await harness.call(
      "POST",
      "/revenuecat-webhook",
      webhookRequest(grant(), "anything"),
    );

    assert.equal(res.statusCode, 401);
    assert.equal(res.body.errors[0].extensions.code, "WEBHOOK_UNAUTHORIZED");
    assert.deepEqual(harness.db.rawCalls, []);
    // An unset secret must be loud at boot, because it means subscriptions silently stop mirroring.
    assert.ok(harness.logs.some((l) => l.message.includes("REVENUECAT_WEBHOOK_SECRET is not set")));
  });

  it("rejects a missing, wrong, and same-length-but-wrong secret", async () => {
    for (const presented of [null, "nope", "s3cret-webhook-tokeN"]) {
      const { program, byUser } = fakeProfiles([fakeProfile(USER)]);
      const harness = mount({ program, env: { REVENUECAT_WEBHOOK_SECRET: SECRET } });

      const res = await harness.call(
        "POST",
        "/revenuecat-webhook",
        webhookRequest(grant(), presented),
      );

      assert.equal(res.statusCode, 401, `presented: ${presented}`);
      assert.deepEqual(harness.db.rawCalls, []);
      assert.equal(byUser.get(USER)!.subscription_tier, "free");
    }
  });
});

describe("revenuecat webhook", () => {
  it("grants premium on TRIAL_STARTED and stores the period end and the event time", async () => {
    const expires = Date.now() + 7 * 24 * hour;
    const eventAt = Date.now() - hour;
    const { program, byUser } = fakeProfiles([fakeProfile(USER)]);
    const harness = mount({ program, env: { REVENUECAT_WEBHOOK_SECRET: SECRET } });

    const res = await harness.call(
      "POST",
      "/revenuecat-webhook",
      webhookRequest(
        grant({
          type: "TRIAL_STARTED",
          period_type: "TRIAL",
          expiration_at_ms: expires,
          event_timestamp_ms: eventAt,
          original_app_user_id: USER,
        }),
      ),
    );

    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body.data, { received: true, matched: true });
    const profile = byUser.get(USER)!;
    assert.equal(profile.subscription_tier, "premium");
    assert.equal(profile.subscription_expires_at!.getTime(), expires);
    assert.equal(profile.subscription_event_at!.getTime(), eventAt);
    assert.equal(profile.revenuecat_id, USER);
    // The guard has to be in the statement, not in a comment about the statement.
    const update = harness.db.rawCalls.find((c) => c.sql.includes("subscription_tier ="))!;
    assert.match(
      update.sql.replace(/\s+/g, " "),
      /subscription_event_at is null or subscription_event_at <= \?/,
    );
  });

  it("takes the highest entitlement when an event carries several", async () => {
    const { program, byUser } = fakeProfiles([fakeProfile(USER)]);
    const harness = mount({ program, env: { REVENUECAT_WEBHOOK_SECRET: SECRET } });

    await harness.call(
      "POST",
      "/revenuecat-webhook",
      webhookRequest(grant({ entitlement_ids: ["premium", "vip"] })),
    );

    assert.equal(byUser.get(USER)!.subscription_tier, "vip");
  });

  it("is idempotent: the same delivery twice leaves the same state", async () => {
    const event = grant({ type: "INITIAL_PURCHASE" });
    const { program, byUser } = fakeProfiles([fakeProfile(USER)]);
    const harness = mount({ program, env: { REVENUECAT_WEBHOOK_SECRET: SECRET } });

    const first = await harness.call("POST", "/revenuecat-webhook", webhookRequest(event));
    const after = { ...byUser.get(USER)! };
    const second = await harness.call("POST", "/revenuecat-webhook", webhookRequest(event));

    assert.equal(first.statusCode, 200);
    assert.equal(second.statusCode, 200);
    assert.deepEqual(byUser.get(USER), after);
  });

  it("ignores an EXPIRATION older than the purchase already applied", async () => {
    // The failure this guard exists for: RevenueCat retries out of order, so the EXPIRATION of a
    // lapsed subscription can land after the INITIAL_PURCHASE of the one that replaced it. Applied
    // in arrival order, it takes premium away from someone who just paid for it.
    const lapsedAt = Date.now() - 2 * hour;
    const resubscribedAt = Date.now() - hour;
    const { program, byUser } = fakeProfiles([fakeProfile(USER)]);
    const harness = mount({ program, env: { REVENUECAT_WEBHOOK_SECRET: SECRET } });

    await harness.call(
      "POST",
      "/revenuecat-webhook",
      webhookRequest(grant({ type: "INITIAL_PURCHASE", event_timestamp_ms: resubscribedAt })),
    );
    const res = await harness.call(
      "POST",
      "/revenuecat-webhook",
      webhookRequest(
        grant({
          type: "EXPIRATION",
          entitlement_ids: ["premium"],
          expiration_at_ms: lapsedAt,
          event_timestamp_ms: lapsedAt,
        }),
      ),
    );

    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body.data, { received: true, matched: false });
    const profile = byUser.get(USER)!;
    assert.equal(profile.subscription_tier, "premium");
    assert.equal(profile.subscription_event_at!.getTime(), resubscribedAt);
  });

  it("downgrades on an EXPIRATION that is the newest event", async () => {
    const { program, byUser } = fakeProfiles([
      fakeProfile(USER, {
        subscription_tier: "premium",
        subscription_event_at: new Date(Date.now() - 2 * hour),
      }),
    ]);
    const harness = mount({ program, env: { REVENUECAT_WEBHOOK_SECRET: SECRET } });

    const res = await harness.call(
      "POST",
      "/revenuecat-webhook",
      // A real EXPIRATION carries a period end that has already passed.
      webhookRequest(grant({ type: "EXPIRATION", expiration_at_ms: Date.now() - 60_000 })),
    );

    assert.equal(res.body.data.matched, true);
    assert.equal(byUser.get(USER)!.subscription_tier, "free");
  });

  it("writes nothing for CANCELLATION or BILLING_ISSUE", async () => {
    // A cancelled auto-renew is still entitled until the period ends, and a billing issue is
    // RevenueCat's own grace period. Both are still-paying users.
    for (const type of ["CANCELLATION", "BILLING_ISSUE"]) {
      const { program, byUser } = fakeProfiles([
        fakeProfile(USER, { subscription_tier: "premium" }),
      ]);
      const harness = mount({ program, env: { REVENUECAT_WEBHOOK_SECRET: SECRET } });

      const res = await harness.call(
        "POST",
        "/revenuecat-webhook",
        webhookRequest(grant({ type })),
      );

      assert.equal(res.statusCode, 200, type);
      assert.deepEqual(harness.db.rawCalls, [], type);
      assert.equal(byUser.get(USER)!.subscription_tier, "premium", type);
    }
  });

  it("does not downgrade a purchase whose entitlement id is unknown to this server", async () => {
    const { program, byUser } = fakeProfiles([fakeProfile(USER, { subscription_tier: "premium" })]);
    const harness = mount({ program, env: { REVENUECAT_WEBHOOK_SECRET: SECRET } });

    const res = await harness.call(
      "POST",
      "/revenuecat-webhook",
      webhookRequest(grant({ entitlement_ids: ["platinum"] })),
    );

    assert.equal(res.statusCode, 200);
    assert.deepEqual(harness.db.rawCalls, []);
    assert.equal(byUser.get(USER)!.subscription_tier, "premium");
    assert.ok(harness.logs.some((l) => l.level === "error" && l.message.includes("platinum")));
  });

  // The profile row is written by the client's onboarding flush and the paywall is shown seconds
  // later, so a purchase landing first is ordinary — not the dead end it was once treated as. This
  // used to assert the event was dropped, which cost the buyer their entitlement until the next
  // RENEWAL: a year on the annual plan, never on a lifetime purchase.
  it("creates the profile row when a grant arrives before the client has written one", async () => {
    const { program, byUser } = fakeProfiles([fakeProfile(OTHER)]);
    const harness = mount({ program, env: { REVENUECAT_WEBHOOK_SECRET: SECRET } });

    const res = await harness.call("POST", "/revenuecat-webhook", webhookRequest(grant()));

    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body.data, { received: true, matched: true });
    assert.equal(byUser.get(USER)?.subscription_tier, "premium");
  });

  // An expiry says "not entitled", and so does the absence of a row. Inventing one to record it
  // would assert something about a user this instance has never seen.
  it("creates no profile row for an expiry it has never seen a purchase for", async () => {
    const { program, byUser } = fakeProfiles([fakeProfile(OTHER)]);
    const harness = mount({ program, env: { REVENUECAT_WEBHOOK_SECRET: SECRET } });

    const res = await harness.call(
      "POST",
      "/revenuecat-webhook",
      webhookRequest(grant({ type: "EXPIRATION" })),
    );

    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body.data, { received: true, matched: false });
    assert.equal(byUser.has(USER), false);
  });

  // A lifetime purchase sends NON_RENEWING_PURCHASE and never renews, so the usual "a later RENEWAL
  // re-asserts the truth" safety net does not exist for it. Ignoring it meant the customer who paid
  // the most got nothing, permanently.
  it("grants on a non-renewing (lifetime) purchase, with no expiry", async () => {
    const { program, byUser } = fakeProfiles([fakeProfile(USER)]);
    const harness = mount({ program, env: { REVENUECAT_WEBHOOK_SECRET: SECRET } });

    const res = await harness.call(
      "POST",
      "/revenuecat-webhook",
      webhookRequest(
        grant({ type: "NON_RENEWING_PURCHASE", expiration_at_ms: null, entitlement_ids: ["vip"] }),
      ),
    );

    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body.data, { received: true, matched: true });
    assert.equal(byUser.get(USER)?.subscription_tier, "vip");
    // Null expiry is what `suvia_is_entitled()` reads as "does not expire".
    assert.equal(byUser.get(USER)?.subscription_expires_at, null);
  });

  // TRANSFER names transferred_from/transferred_to instead of an app_user_id, so it needs its own
  // path — through the ordinary one every check read undefined and the event fell out unapplied,
  // leaving the receiving account un-entitled until its next renewal.
  it("moves the entitlement across on a transfer, and takes it off the giving side", async () => {
    const { program, byUser } = fakeProfiles([
      fakeProfile(OTHER, { subscription_tier: "premium" }),
      fakeProfile(USER),
    ]);
    const harness = mount({ program, env: { REVENUECAT_WEBHOOK_SECRET: SECRET } });

    const res = await harness.call(
      "POST",
      "/revenuecat-webhook",
      webhookRequest(
        grant({
          type: "TRANSFER",
          app_user_id: undefined,
          transferred_from: [OTHER],
          transferred_to: [USER],
        }),
      ),
    );

    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body.data, { received: true, matched: true });
    assert.equal(byUser.get(USER)?.subscription_tier, "premium");
    assert.equal(byUser.get(OTHER)?.subscription_tier, "free");
  });

  it("answers 200 for an anonymous or malformed app_user_id without querying", async () => {
    const { program } = fakeProfiles([fakeProfile(USER)]);
    const harness = mount({ program, env: { REVENUECAT_WEBHOOK_SECRET: SECRET } });

    const res = await harness.call(
      "POST",
      "/revenuecat-webhook",
      webhookRequest(grant({ app_user_id: "$RCAnonymousID:9f2c" })),
    );

    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body.data, { received: true, matched: false });
    assert.deepEqual(harness.db.rawCalls, []);
  });

  it("answers 200 without writing when the event carries no timestamp to order it by", async () => {
    const { program, byUser } = fakeProfiles([fakeProfile(USER)]);
    const harness = mount({ program, env: { REVENUECAT_WEBHOOK_SECRET: SECRET } });

    const res = await harness.call(
      "POST",
      "/revenuecat-webhook",
      webhookRequest(grant({ event_timestamp_ms: null })),
    );

    assert.equal(res.statusCode, 200);
    assert.deepEqual(harness.db.rawCalls, []);
    assert.equal(byUser.get(USER)!.subscription_tier, "free");
  });
});

describe("highestTier", () => {
  it("ranks vip above premium and treats anything else as no entitlement", () => {
    assert.equal(highestTier(["premium"]), "premium");
    assert.equal(highestTier(["vip", "premium"]), "vip");
    assert.equal(highestTier(["premium", "vip"]), "vip");
    assert.equal(highestTier([]), "free");
    assert.equal(highestTier(["free"]), "free");
    assert.equal(highestTier(["platinum"]), "free");
    assert.equal(highestTier(undefined), "free");
    assert.equal(highestTier("premium"), "free");
  });
});
