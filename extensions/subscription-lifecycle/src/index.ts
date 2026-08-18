import {
  DEFAULT_WARNING_DAYS,
  EXPO_PUSH_BATCH_SIZE,
  EXPO_PUSH_URL,
  buildExpiredNotification,
  buildPushMessages,
  buildWarningNotification,
  chunk,
  normalizeVenueId,
  selectUsersToWarn,
  type NotificationPayload,
  type SubscriberRow,
} from "./lifecycle.js";

/**
 * Runs once a day at 09:00 Europe/Istanbul. The container clock is UTC, and a
 * push at 03:00 local is worse than no push, so the default is deliberate.
 */
const DEFAULT_CRON = "0 6 * * *";

const USER_FIELDS = ["id", "venue_id", "subscription_expires_at", "push_token"];

interface HookEvents {
  schedule(cron: string, handler: () => Promise<void> | void): void;
}

export default ({ schedule }: HookEvents, context: any) => {
  const { env, services, getSchema, logger } = context;

  const DEFAULT_ROLE_ID = String(env["SSO_DEFAULT_ROLE_ID"] || "");
  const WARNING_DAYS = Number(env["SUBSCRIPTION_WARNING_DAYS"] || DEFAULT_WARNING_DAYS);
  const CRON = String(env["SUBSCRIPTION_SWEEP_CRON"] || DEFAULT_CRON);

  if (!DEFAULT_ROLE_ID) {
    // Without it the sweep can still drop the tier, but the Business role — the
    // thing that actually grants server-side access — would stay on the account.
    logger.error(
      "[subscriptions] SSO_DEFAULT_ROLE_ID is not set — expired accounts will keep their Business role",
    );
  }

  async function getServices() {
    const schema = await getSchema();
    const options = { schema, accountability: { admin: true } };
    return {
      users: new services.UsersService(options),
      subscriptions: new services.ItemsService("subscriptions", options),
      notifications: new services.ItemsService("notifications", options),
      venues: new services.ItemsService("venues", options),
    };
  }

  async function readVenueNames(
    venuesService: any,
    users: SubscriberRow[],
  ): Promise<Map<number, string>> {
    const ids = [...new Set(users.map((user) => normalizeVenueId(user.venue_id)).filter(Boolean))];
    if (ids.length === 0) return new Map();

    const rows = await venuesService.readByQuery({
      filter: { id: { _in: ids } },
      fields: ["id", "name"],
      limit: -1,
    });

    return new Map(rows.map((row: any) => [Number(row.id), String(row.name ?? "")]));
  }

  /**
   * Writes the in-app rows first and pushes afterwards: the notification list is
   * the durable record, and a failing Expo call must not lose it.
   */
  async function deliver(
    notificationsService: any,
    payloads: NotificationPayload[],
    users: SubscriberRow[],
  ): Promise<void> {
    if (payloads.length === 0) return;

    const createdIds: any[] = await notificationsService.createMany(payloads);

    const tokensByUser = new Map(users.map((user) => [user.id, user.push_token]));
    const messages = buildPushMessages(payloads, tokensByUser);
    if (messages.length === 0) return;

    try {
      for (const batch of chunk(messages, EXPO_PUSH_BATCH_SIZE)) {
        const response = await fetch(EXPO_PUSH_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json", Accept: "application/json" },
          body: JSON.stringify(batch),
        });
        if (!response.ok) {
          throw new Error(`Expo push responded ${response.status}: ${await response.text()}`);
        }
      }

      // createMany returns the new keys in payload order, so a payload with a
      // push token maps to the id at the same index.
      const sentIds = createdIds.filter((_, index) => {
        const payload = payloads[index];
        return payload ? Boolean(tokensByUser.get(payload.recipient_id)) : false;
      });
      if (sentIds.length > 0) {
        await notificationsService.updateMany(sentIds, {
          is_sent: true,
          sent_at: new Date().toISOString(),
        });
      }
    } catch (err: any) {
      // The in-app notifications are already stored; a push failure is logged
      // and left for the next sweep rather than rolled back.
      logger.error(`[subscriptions] push delivery failed: ${err.message}`);
    }
  }

  async function expireLapsedSubscriptions(nowIso: string): Promise<number> {
    const { users, subscriptions, notifications, venues } = await getServices();

    const lapsed: SubscriberRow[] = await users.readByQuery({
      filter: {
        subscription_tier: { _eq: "pro" },
        subscription_expires_at: { _lt: nowIso },
      },
      fields: USER_FIELDS,
      limit: -1,
    });

    if (lapsed.length === 0) return 0;

    const userUpdate: Record<string, any> = { subscription_tier: "free" };
    if (DEFAULT_ROLE_ID) userUpdate.role = DEFAULT_ROLE_ID;
    await users.updateMany(
      lapsed.map((user) => user.id),
      userUpdate,
    );

    const venueIds = [...new Set(lapsed.map((user) => normalizeVenueId(user.venue_id)).filter(Boolean))];
    if (venueIds.length > 0) {
      const rows = await subscriptions.readByQuery({
        filter: {
          venue_id: { _in: venueIds },
          subscription_status: { _in: ["active", "trial"] },
        },
        fields: ["id"],
        limit: -1,
      });
      if (rows.length > 0) {
        await subscriptions.updateMany(
          rows.map((row: any) => row.id),
          { subscription_status: "expired" },
        );
      }
    }

    const venueNames = await readVenueNames(venues, lapsed);
    await deliver(
      notifications,
      lapsed.map((user) =>
        buildExpiredNotification(user, venueNames.get(normalizeVenueId(user.venue_id) ?? -1) ?? null),
      ),
      lapsed,
    );

    logger.info(`[subscriptions] expired ${lapsed.length} account(s)`);
    return lapsed.length;
  }

  async function warnExpiringSubscriptions(nowMs: number, nowIso: string): Promise<number> {
    const { users, notifications, venues } = await getServices();

    const windowEnd = new Date(nowMs + WARNING_DAYS * 24 * 60 * 60 * 1000).toISOString();
    const expiring: SubscriberRow[] = await users.readByQuery({
      filter: {
        subscription_tier: { _eq: "pro" },
        subscription_expires_at: { _between: [nowIso, windowEnd] },
      },
      fields: USER_FIELDS,
      limit: -1,
    });

    if (expiring.length === 0) return 0;

    // One warning per period: anything sent inside the window already covers the
    // period that is about to end.
    const windowStart = new Date(nowMs - WARNING_DAYS * 24 * 60 * 60 * 1000).toISOString();
    const alreadyWarned = await notifications.readByQuery({
      filter: {
        notification_type: { _eq: "subscription_warning" },
        recipient_id: { _in: expiring.map((user) => user.id) },
        date_created: { _gte: windowStart },
      },
      fields: ["recipient_id"],
      limit: -1,
    });

    const warnedIds = new Set<string>(alreadyWarned.map((row: any) => String(row.recipient_id)));
    const targets = selectUsersToWarn(expiring, warnedIds, nowMs, WARNING_DAYS);
    if (targets.length === 0) return 0;

    const venueNames = await readVenueNames(
      venues,
      targets.map((target) => target.user),
    );
    await deliver(
      notifications,
      targets.map(({ user, daysRemaining }) =>
        buildWarningNotification(
          user,
          daysRemaining,
          venueNames.get(normalizeVenueId(user.venue_id) ?? -1) ?? null,
        ),
      ),
      targets.map((target) => target.user),
    );

    logger.info(`[subscriptions] warned ${targets.length} account(s)`);
    return targets.length;
  }

  async function sweep(): Promise<void> {
    const nowMs = Date.now();
    const nowIso = new Date(nowMs).toISOString();

    try {
      // Expiry runs first so an account that lapsed overnight is downgraded
      // before it can also be picked up as "expiring soon".
      const expired = await expireLapsedSubscriptions(nowIso);
      const warned = await warnExpiringSubscriptions(nowMs, nowIso);
      logger.info(`[subscriptions] sweep complete: expired=${expired} warned=${warned}`);
    } catch (err: any) {
      logger.error(`[subscriptions] sweep failed: ${err.message}\n${err.stack}`);
    }
  }

  schedule(CRON, sweep);
  logger.info(`[subscriptions] daily sweep scheduled: cron="${CRON}" warningDays=${WARNING_DAYS}`);
};
