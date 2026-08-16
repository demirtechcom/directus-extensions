import { describe, expect, it } from "bun:test";

import {
  buildSubscriptionPayload,
  computeExpiry,
  isPaymentAlreadyApplied,
  resolveDurationDays,
  toDateOnly,
} from "./subscription";

const DAY = 24 * 60 * 60 * 1000;
const now = Date.parse("2026-08-16T10:00:00.000Z");

describe("resolveDurationDays", () => {
  it("accepts a positive whole number of days", () => {
    expect(resolveDurationDays(30)).toBe(30);
    expect(resolveDurationDays("30")).toBe(30);
  });

  it("refuses a plan that cannot produce a period", () => {
    for (const bad of [0, -1, 1.5, null, undefined, "", "monthly"]) {
      expect(() => resolveDurationDays(bad)).toThrow();
    }
  });
});

describe("computeExpiry", () => {
  it("starts from now when there is no subscription yet", () => {
    expect(computeExpiry(null, 30, now).toISOString()).toBe("2026-09-15T10:00:00.000Z");
  });

  it("starts from now when the previous period already lapsed", () => {
    const lapsed = new Date(now - 10 * DAY).toISOString();
    expect(computeExpiry(lapsed, 30, now).toISOString()).toBe("2026-09-15T10:00:00.000Z");
  });

  it("stacks onto the remaining days when renewing early", () => {
    const running = new Date(now + 5 * DAY).toISOString();
    // 5 days left + 30 purchased = 35 days from now, not 30.
    expect(computeExpiry(running, 30, now).toISOString()).toBe("2026-09-20T10:00:00.000Z");
  });

  it("uses the plan duration rather than a fixed month", () => {
    expect(computeExpiry(null, 365, now).toISOString()).toBe("2027-08-16T10:00:00.000Z");
  });

  it("treats an unparseable stored expiry as no subscription", () => {
    expect(computeExpiry("not-a-date", 30, now).toISOString()).toBe("2026-09-15T10:00:00.000Z");
  });
});

describe("buildSubscriptionPayload", () => {
  const expiry = new Date(now + 30 * DAY);

  it("opens a period today when the venue has no subscription row", () => {
    expect(buildSubscriptionPayload(null, 4, 261, expiry, now)).toEqual({
      plan_id: 4,
      subscription_status: "active",
      start_date: "2026-08-16",
      end_date: "2026-09-15",
      auto_renew: true,
      last_payment_id: 261,
    });
  });

  it("keeps the original start date while the period is still running", () => {
    const existing = {
      id: 7,
      start_date: "2026-07-20",
      end_date: "2026-08-19",
      last_payment_id: 130,
    };
    expect(buildSubscriptionPayload(existing, 4, 261, expiry, now).start_date).toBe("2026-07-20");
  });

  it("restarts the period when the previous one had lapsed", () => {
    const existing = {
      id: 7,
      start_date: "2026-06-01",
      end_date: "2026-07-01",
      last_payment_id: 130,
    };
    expect(buildSubscriptionPayload(existing, 4, 261, expiry, now).start_date).toBe("2026-08-16");
  });
});

describe("isPaymentAlreadyApplied", () => {
  it("is false for a venue with no subscription row", () => {
    expect(isPaymentAlreadyApplied(null, 261)).toBe(false);
  });

  it("is true only for the payment that produced the current period", () => {
    const existing = { id: 7, start_date: null, end_date: null, last_payment_id: 261 };
    expect(isPaymentAlreadyApplied(existing, 261)).toBe(true);
    expect(isPaymentAlreadyApplied(existing, 262)).toBe(false);
  });
});

describe("toDateOnly", () => {
  it("formats in UTC so a period boundary does not shift per server timezone", () => {
    expect(toDateOnly(Date.parse("2026-08-16T23:30:00.000Z"))).toBe("2026-08-16");
  });
});
