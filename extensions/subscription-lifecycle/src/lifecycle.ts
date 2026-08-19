/**
 * Selection rules and message shapes for the daily subscription sweep.
 *
 * Everything here is pure so the "who gets warned, who gets downgraded" logic
 * can be tested without a Directus instance. The side effects live in index.ts.
 */

export const DAY_IN_MS = 24 * 60 * 60 * 1000;
export const DEFAULT_WARNING_DAYS = 3;
export const EXPO_PUSH_URL = "https://exp.host/--/api/v2/push/send";
export const EXPO_PUSH_BATCH_SIZE = 100;

export interface SubscriberRow {
  id: string;
  venue_id: number | { id: number } | null;
  subscription_expires_at: string | null;
  push_token?: string | null;
  role?: string | { id: string } | null;
}

export interface NotificationPayload {
  recipient_id: string;
  sender_type: "system";
  sender_venue_id: number | null;
  notification_type: "subscription_warning" | "subscription_expired";
  title: string;
  body: string;
  data: Record<string, unknown>;
  is_read: false;
  is_sent: false;
}

export interface PushMessage {
  to: string;
  title: string;
  body: string;
  sound: "default";
  data: Record<string, unknown>;
}

export function normalizeVenueId(value: SubscriberRow["venue_id"]): number | null {
  const raw = value !== null && typeof value === "object" ? value.id : value;
  const id = Number(raw);
  return Number.isInteger(id) && id > 0 ? id : null;
}

export function normalizeRoleId(value: SubscriberRow["role"]): string | null {
  const raw = value !== null && typeof value === "object" ? value?.id : value;
  return typeof raw === "string" && raw.length > 0 ? raw : null;
}

/**
 * Splits the lapsed accounts into the ones whose role may be rewritten and the
 * ones that only lose their tier.
 *
 * The sweep exists to revoke *business* entitlement, and its earlier form set
 * `role = SSO_DEFAULT_ROLE_ID` on every lapsed account regardless of what role it
 * held. On 2026-08-19 that demoted a Directus `Administrator` and a
 * `Delivr Admin Role` account to `app user`, because both happened to carry
 * `subscription_tier = 'pro'` with an expiry in the past. Dropping the tier is
 * always correct; rewriting a role that was never granted by a subscription is not.
 *
 * An empty businessRoleId demotes nobody. That is the deliberate failure mode: a
 * missing config leaves stale business access in place, which is visible and
 * fixable, where the alternative silently rewrites every role in the cohort.
 */
export function partitionRoleUpdates(
  users: SubscriberRow[],
  businessRoleId: string,
): { demote: SubscriberRow[]; tierOnly: SubscriberRow[] } {
  if (!businessRoleId) return { demote: [], tierOnly: users };

  const demote: SubscriberRow[] = [];
  const tierOnly: SubscriberRow[] = [];

  for (const user of users) {
    if (normalizeRoleId(user.role) === businessRoleId) demote.push(user);
    else tierOnly.push(user);
  }

  return { demote, tierOnly };
}

/**
 * Whole days left, rounded up: an expiry 2.1 days away is "3 days left" to a
 * customer, and rounding down would skip the last warning entirely.
 */
export function daysUntil(expiresAt: string | null, nowMs: number): number | null {
  if (!expiresAt) return null;
  const expiry = Date.parse(expiresAt);
  if (!Number.isFinite(expiry)) return null;
  return Math.ceil((expiry - nowMs) / DAY_IN_MS);
}

/**
 * Users whose period ends inside the warning window and who have not already
 * been warned for this period. Dedupe is by recipient rather than by period id
 * because a warning is only ever sent in the last few days of a period.
 */
export function selectUsersToWarn(
  users: SubscriberRow[],
  alreadyWarnedIds: Set<string>,
  nowMs: number,
  warningDays: number = DEFAULT_WARNING_DAYS,
): Array<{ user: SubscriberRow; daysRemaining: number }> {
  const selected: Array<{ user: SubscriberRow; daysRemaining: number }> = [];

  for (const user of users) {
    if (alreadyWarnedIds.has(user.id)) continue;
    const daysRemaining = daysUntil(user.subscription_expires_at, nowMs);
    if (daysRemaining === null || daysRemaining <= 0 || daysRemaining > warningDays) continue;
    selected.push({ user, daysRemaining });
  }

  return selected;
}

function formatDate(expiresAt: string | null): string {
  if (!expiresAt) return "";
  const parsed = Date.parse(expiresAt);
  if (!Number.isFinite(parsed)) return "";
  const date = new Date(parsed);
  return `${String(date.getUTCDate()).padStart(2, "0")}.${String(date.getUTCMonth() + 1).padStart(2, "0")}.${date.getUTCFullYear()}`;
}

/**
 * Copy is Turkish and lives here rather than in the app's i18n bundle because
 * these rows are written server-side and rendered verbatim from the database.
 */
export function buildWarningNotification(
  user: SubscriberRow,
  daysRemaining: number,
  venueName: string | null,
): NotificationPayload {
  const subject = venueName ? `${venueName} aboneliği` : "Aboneliğiniz";
  return {
    recipient_id: user.id,
    sender_type: "system",
    sender_venue_id: normalizeVenueId(user.venue_id),
    notification_type: "subscription_warning",
    title: `Aboneliğiniz ${daysRemaining} gün sonra bitiyor`,
    body: `${subject} ${formatDate(user.subscription_expires_at)} tarihinde sona eriyor. Kesintisiz devam etmek için yenileyin.`,
    data: {
      type: "subscription_warning",
      venue_id: normalizeVenueId(user.venue_id),
      expires_at: user.subscription_expires_at,
      days_remaining: daysRemaining,
    },
    is_read: false,
    is_sent: false,
  };
}

export function buildExpiredNotification(
  user: SubscriberRow,
  venueName: string | null,
): NotificationPayload {
  const subject = venueName ? `${venueName} için` : "Hesabınızda";
  return {
    recipient_id: user.id,
    sender_type: "system",
    sender_venue_id: normalizeVenueId(user.venue_id),
    notification_type: "subscription_expired",
    title: "Aboneliğiniz sona erdi",
    body: `${subject} Pro özellikler kapandı. Yeniden açmak için aboneliğinizi yenileyebilirsiniz.`,
    data: {
      type: "subscription_expired",
      venue_id: normalizeVenueId(user.venue_id),
      expires_at: user.subscription_expires_at,
    },
    is_read: false,
    is_sent: false,
  };
}

export function buildPushMessages(
  notifications: NotificationPayload[],
  pushTokensByUser: Map<string, string | null | undefined>,
): PushMessage[] {
  const messages: PushMessage[] = [];

  for (const notification of notifications) {
    const token = pushTokensByUser.get(notification.recipient_id);
    if (!token) continue;
    messages.push({
      to: token,
      title: notification.title,
      body: notification.body,
      sound: "default",
      data: notification.data,
    });
  }

  return messages;
}

export function chunk<T>(items: T[], size: number): T[][] {
  const batches: T[][] = [];
  for (let index = 0; index < items.length; index += size) {
    batches.push(items.slice(index, index + size));
  }
  return batches;
}
