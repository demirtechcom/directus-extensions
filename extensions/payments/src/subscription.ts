/**
 * Subscription period maths.
 *
 * Kept pure and separate from the router so the renewal rules can be tested
 * without a Directus instance: getting these wrong silently costs a paying
 * customer days, which nobody notices until they complain.
 */

const DAY_IN_MS = 24 * 60 * 60 * 1000;

export interface SubscriptionRow {
  id: number;
  start_date: string | null;
  end_date: string | null;
  last_payment_id: number | null;
}

export interface SubscriptionPayload {
  plan_id: number;
  subscription_status: "active";
  start_date: string;
  end_date: string;
  auto_renew: boolean;
  last_payment_id: number;
}

export function parseTimestamp(value: string | null | undefined): number | null {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

export function resolveDurationDays(raw: unknown): number {
  const days = Number(raw);
  if (!Number.isInteger(days) || days <= 0) {
    throw new Error(`Subscription plan has an unusable duration_days: ${JSON.stringify(raw)}`);
  }
  return days;
}

/**
 * A renewal extends the period the customer already paid for, it does not
 * replace it. Renewing five days early has to leave 35 days, not 30.
 * Only a lapsed subscription restarts from now.
 */
export function computeExpiry(
  currentExpiresAt: string | null | undefined,
  durationDays: number,
  nowMs: number,
): Date {
  const current = parseTimestamp(currentExpiresAt);
  const base = current !== null && current > nowMs ? current : nowMs;
  return new Date(base + durationDays * DAY_IN_MS);
}

export function toDateOnly(value: Date | number): string {
  return new Date(value).toISOString().slice(0, 10);
}

/**
 * `subscriptions` is venue-scoped and holds one row per venue, so a renewal
 * patches the existing row rather than stacking rows. The period start only
 * moves when the previous period had already lapsed.
 */
export function buildSubscriptionPayload(
  existing: SubscriptionRow | null,
  planId: number,
  paymentId: number,
  expiry: Date,
  nowMs: number,
): SubscriptionPayload {
  const today = toDateOnly(nowMs);
  const stillRunning = existing?.end_date != null && existing.end_date > today;

  return {
    plan_id: planId,
    subscription_status: "active",
    start_date: stillRunning && existing?.start_date ? existing.start_date : today,
    end_date: toDateOnly(expiry),
    auto_renew: true,
    last_payment_id: paymentId,
  };
}

/**
 * Both the provider callback and the client's /check-status poll can reach the
 * activation path for the same payment. Extending the period twice for one
 * payment is a real risk now that renewals stack, so a payment that was already
 * applied to the venue's subscription must not be applied again.
 */
export function isPaymentAlreadyApplied(
  existing: SubscriptionRow | null,
  paymentId: number,
): boolean {
  return existing?.last_payment_id != null && Number(existing.last_payment_id) === paymentId;
}
