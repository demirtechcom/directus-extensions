import { describe, expect, it } from "bun:test";

import {
  buildExpiredNotification,
  buildPushMessages,
  buildWarningNotification,
  chunk,
  daysUntil,
  normalizeRoleId,
  normalizeVenueId,
  partitionRoleUpdates,
  selectUsersToWarn,
  type SubscriberRow,
} from "./lifecycle";

const BUSINESS_ROLE = "82975326-5ec3-4bec-aa72-2aadb2d48be9";
const ADMIN_ROLE = "90b057e7-58f3-490c-a28f-132934291692";
const APP_USER_ROLE = "821c72fe-661e-4a30-8647-d447de7649ef";

const DAY = 24 * 60 * 60 * 1000;
const now = Date.parse("2026-08-16T06:00:00.000Z");

function user(overrides: Partial<SubscriberRow> = {}): SubscriberRow {
  return {
    id: "87d1a87a-9771-4886-8dc6-2fc8ee022c03",
    venue_id: 51,
    subscription_expires_at: new Date(now + 2 * DAY).toISOString(),
    push_token: "ExponentPushToken[abc]",
    ...overrides,
  };
}

describe("normalizeRoleId", () => {
  it("accepts both a raw id and an expanded relation", () => {
    expect(normalizeRoleId(BUSINESS_ROLE)).toBe(BUSINESS_ROLE);
    expect(normalizeRoleId({ id: BUSINESS_ROLE })).toBe(BUSINESS_ROLE);
  });

  it("returns null for a missing role", () => {
    expect(normalizeRoleId(null)).toBeNull();
    expect(normalizeRoleId(undefined)).toBeNull();
    expect(normalizeRoleId("")).toBeNull();
  });
});

describe("partitionRoleUpdates", () => {
  it("revokes the role only from accounts holding the business role", () => {
    const business = user({ id: "business", role: BUSINESS_ROLE });
    const admin = user({ id: "admin", role: ADMIN_ROLE });
    const appUser = user({ id: "app", role: APP_USER_ROLE });

    const { demote, tierOnly } = partitionRoleUpdates(
      [business, admin, appUser],
      BUSINESS_ROLE,
    );

    expect(demote.map((u) => u.id)).toEqual(["business"]);
    expect(tierOnly.map((u) => u.id)).toEqual(["admin", "app"]);
  });

  it("leaves an administrator alone - the 2026-08-19 regression", () => {
    const admin = user({ id: "admin", role: ADMIN_ROLE });

    const { demote } = partitionRoleUpdates([admin], BUSINESS_ROLE);

    expect(demote).toEqual([]);
  });

  it("treats an expanded role relation the same as a raw id", () => {
    const business = user({ id: "business", role: { id: BUSINESS_ROLE } });

    const { demote } = partitionRoleUpdates([business], BUSINESS_ROLE);

    expect(demote.map((u) => u.id)).toEqual(["business"]);
  });

  it("keeps a roleless account out of the demote set", () => {
    const roleless = user({ id: "none", role: null });

    const { demote, tierOnly } = partitionRoleUpdates([roleless], BUSINESS_ROLE);

    expect(demote).toEqual([]);
    expect(tierOnly.map((u) => u.id)).toEqual(["none"]);
  });

  it("demotes nobody when BUSINESS_ROLE_ID is unset, rather than everybody", () => {
    const business = user({ id: "business", role: BUSINESS_ROLE });
    const admin = user({ id: "admin", role: ADMIN_ROLE });

    const { demote, tierOnly } = partitionRoleUpdates([business, admin], "");

    expect(demote).toEqual([]);
    expect(tierOnly.map((u) => u.id)).toEqual(["business", "admin"]);
  });
});

describe("normalizeVenueId", () => {
  it("accepts both a raw id and an expanded relation", () => {
    expect(normalizeVenueId(51)).toBe(51);
    expect(normalizeVenueId({ id: 51 })).toBe(51);
  });

  it("returns null when the business has no venue yet", () => {
    expect(normalizeVenueId(null)).toBeNull();
    expect(normalizeVenueId(0)).toBeNull();
  });
});

describe("daysUntil", () => {
  it("rounds up so the last partial day still counts", () => {
    expect(daysUntil(new Date(now + 2.1 * DAY).toISOString(), now)).toBe(3);
    expect(daysUntil(new Date(now + 3 * DAY).toISOString(), now)).toBe(3);
  });

  it("goes negative once the period has ended", () => {
    expect(daysUntil(new Date(now - 1 * DAY).toISOString(), now)).toBe(-1);
  });

  it("returns null for missing or unparseable values", () => {
    expect(daysUntil(null, now)).toBeNull();
    expect(daysUntil("whenever", now)).toBeNull();
  });
});

describe("selectUsersToWarn", () => {
  it("takes accounts inside the window", () => {
    const selected = selectUsersToWarn([user()], new Set(), now);
    expect(selected).toHaveLength(1);
    expect(selected[0]!.daysRemaining).toBe(2);
  });

  it("skips accounts that are already past the window", () => {
    const far = user({ subscription_expires_at: new Date(now + 10 * DAY).toISOString() });
    expect(selectUsersToWarn([far], new Set(), now)).toHaveLength(0);
  });

  it("skips accounts that already expired — those are the sweep's other pass", () => {
    const lapsed = user({ subscription_expires_at: new Date(now - 1 * DAY).toISOString() });
    expect(selectUsersToWarn([lapsed], new Set(), now)).toHaveLength(0);
  });

  it("warns once per period", () => {
    const target = user();
    expect(selectUsersToWarn([target], new Set([target.id]), now)).toHaveLength(0);
  });

  it("honours a custom warning window", () => {
    const target = user({ subscription_expires_at: new Date(now + 6 * DAY).toISOString() });
    expect(selectUsersToWarn([target], new Set(), now, 3)).toHaveLength(0);
    expect(selectUsersToWarn([target], new Set(), now, 7)).toHaveLength(1);
  });
});

describe("notification payloads", () => {
  it("names the venue in the warning when it is known", () => {
    const payload = buildWarningNotification(user(), 2, "Berliner Brezel");
    expect(payload.title).toBe("Aboneliğiniz 2 gün sonra bitiyor");
    expect(payload.body).toContain("Berliner Brezel aboneliği");
    expect(payload.body).toContain("18.08.2026");
    expect(payload.notification_type).toBe("subscription_warning");
    expect(payload.sender_venue_id).toBe(51);
    expect(payload.is_sent).toBe(false);
  });

  it("falls back to generic copy when the business has no venue", () => {
    const payload = buildWarningNotification(user({ venue_id: null }), 1, null);
    expect(payload.body).toContain("Aboneliğiniz");
    expect(payload.sender_venue_id).toBeNull();
  });

  it("marks the expiry notification with its own type", () => {
    const payload = buildExpiredNotification(user(), "Berliner Brezel");
    expect(payload.notification_type).toBe("subscription_expired");
    expect(payload.data).toMatchObject({ type: "subscription_expired", venue_id: 51 });
  });
});

describe("buildPushMessages", () => {
  it("only builds messages for accounts with a push token", () => {
    const withToken = user();
    const withoutToken = user({ id: "no-token-user", push_token: null });
    const payloads = [
      buildWarningNotification(withToken, 2, null),
      buildWarningNotification(withoutToken, 2, null),
    ];

    const messages = buildPushMessages(
      payloads,
      new Map([
        [withToken.id, withToken.push_token],
        [withoutToken.id, withoutToken.push_token],
      ]),
    );

    expect(messages).toHaveLength(1);
    expect(messages[0]!.to).toBe("ExponentPushToken[abc]");
    expect(messages[0]!.sound).toBe("default");
  });
});

describe("chunk", () => {
  it("splits into batches the push API accepts", () => {
    expect(chunk([1, 2, 3, 4, 5], 2)).toEqual([[1, 2], [3, 4], [5]]);
    expect(chunk([], 100)).toEqual([]);
  });
});
