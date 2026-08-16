# Subscription Lifecycle Extension

Directus hook extension that runs the daily subscription sweep for Delivr: it warns businesses
before their period ends and downgrades the ones that have lapsed.

It is the counterpart of the [`payments`](../payments/) endpoint, which opens and extends periods.
Nothing else in the stack ends a subscription.

## What the sweep does

Once a day, in this order:

1. **Expire.** Every user with `subscription_tier = 'pro'` and `subscription_expires_at` in the past
   gets `subscription_tier = 'free'` and their role reverted to `SSO_DEFAULT_ROLE_ID`. The venue's
   `subscriptions` rows move from `active`/`trial` to `expired`. A `subscription_expired`
   notification is written and pushed.
2. **Warn.** Every user whose period ends inside the warning window (3 days by default) gets a
   `subscription_warning` notification and push, once per period.

Expiry runs first so an account that lapsed overnight is downgraded rather than warned.

The tier alone is not the entitlement: the app reads `subscription_tier`, but server-side access
comes from the Directus **role**, which is why the sweep reverts both. Leaving the role behind is
how expired accounts kept Business permissions.

## Delivery model

In-app `notifications` rows are written first and the Expo push is sent afterwards. The rows are the
durable record; a failing push is logged and the rows stay, rather than the whole sweep rolling back.
Rows are marked `is_sent` only for recipients that actually had a push token and whose batch was
accepted.

Warnings dedupe on `notifications`: a `subscription_warning` written to the same recipient inside the
window means the period was already covered.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SSO_DEFAULT_ROLE_ID` | yes | — | Role a lapsed account is reverted to. Without it the sweep drops the tier but leaves Business permissions, and boots with an error log. |
| `SUBSCRIPTION_SWEEP_CRON` | no | `0 6 * * *` | Server clock is UTC; the default is 09:00 Europe/Istanbul, chosen so nobody is pushed at 03:00 local. |
| `SUBSCRIPTION_WARNING_DAYS` | no | `3` | How many days before expiry the warning goes out. |

## Collections it touches

- `directus_users` — reads `subscription_tier`, `subscription_expires_at`, `venue_id`, `push_token`;
  writes `subscription_tier`, `role`
- `subscriptions` — writes `subscription_status`
- `notifications` — creates `subscription_warning` / `subscription_expired` rows
- `venues` — reads `name` for the notification copy

Notification copy is Turkish and lives in `src/lifecycle.ts`: these rows are written server-side and
rendered verbatim from the database, so they cannot go through the app's i18n bundle.

## Development

```bash
bun install
bun test          # pure selection + copy rules
bun run build     # dist/index.js
```

## Installation

Same ConfigMap path as the other extensions — see the [payments README](../payments/README.md#installation).
`EXTENSIONS_AUTO_RELOAD=false`, so the pod must restart before a new build is live. Commit `src/`
and `dist/` together.

Confirm it is loaded by looking for this line in the pod log at boot:

```
[subscriptions] daily sweep scheduled: cron="0 6 * * *" warningDays=3
```

## License

MIT
