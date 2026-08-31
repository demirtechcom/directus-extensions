# Payments Extension

Directus endpoint extension for subscription payments and isolated PayTR marketplace order payments.

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/payments/get-token` | Required | Generate payment iframe token |
| `GET` | `/payments/check-status` | Required | Check payment status via provider API |
| `POST` | `/payments/callback` | Public | Webhook called by payment provider |
| `POST` | `/payments/orders` | Conditional | Atomically create an idempotent Delivr order |
| `POST` | `/payments/orders/:id/payment-attempts` | Customer | Reconcile the previous attempt and create a 15-minute PayTR iFrame attempt |
| `GET` | `/payments/orders/:id/payment-status` | Customer | Return verified payment, acceptance, retry, and delivery-code state |
| `POST` | `/payments/paytr/callback` | Public | Verify the order callback HMAC, amount, currency, and status query |
| `POST` | `/payments/orders/:id/accept` | Restaurant | Accept a paid order within five minutes |
| `POST` | `/payments/orders/:id/cancel` | Customer or restaurant | Cancel before preparation and fully refund captured funds |
| `POST` | `/payments/orders/:id/refunds` | Admin | Issue an amount or item-based partial refund |
| `POST` | `/payments/orders/:id/delivery-verification` | Restaurant | Verify the rate-limited six-digit delivery code |
| `POST` | `/payments/payouts/:id/transfers` | Admin | Submit an eligible PayTR platform transfer instruction |
| `POST` | `/payments/venues/:id/payment-account` | Restaurant or admin | Submit encrypted payout-account details and payment preferences |
| `POST` | `/payments/venues/:id/payment-account/review` | Admin | Approve, reject, or suspend a submerchant account |
| `GET` | `/payments/ok` | Public | Browser redirect after successful payment |
| `GET` | `/payments/fail` | Public | Browser redirect after failed payment |

### POST /payments/get-token

Request (authenticated):
```json
{ "plan_id": 4 }
```

Response:
```json
{
  "token": "28cc613c3d7633cfa4ed...",
  "merchant_oid": "DLVR6f265eca1749212345678"
}
```

### GET /payments/check-status?merchant_oid=DLVR...

Queries the payment provider's status API and updates the payment record + subscription on success.
Returns `403` if the payment belongs to another user, `404` if `merchant_oid` is unknown.

Response:
```json
{ "payment_status": "success", "role_updated": true }
```

`role_updated: true` means the user's role changed server-side; the client must call
`/sso-exchange/refresh` for the new permissions to apply to its access token.

### POST /payments/callback

Called by the payment provider after payment completes. Verifies the HMAC-SHA256 hash, updates the payment record, and activates the user's subscription. Must return plain text `OK`.

### POST /payments/orders

Creates the order, its line items, and (for QR, WhatsApp, and direct orders) its
business-collected payment record in one database transaction. Prices and the
total are loaded from published products on the server; client-supplied prices
are not accepted. `client_request_id` is a UUID idempotency key and must be
reused when retrying an uncertain request.

Customer sources (`qr_table`, `whatsapp`) may be submitted without a session.
Business and marketplace sources require an authenticated user assigned to the
submitted venue.

Request:

```json
{
  "client_request_id": "c66c8d41-e3ec-4cf4-b63e-cbae1b82fb22",
  "venue_id": 12,
  "table_id": 31,
  "table_number": 4,
  "order_source": "qr_table",
  "customer_name": "Ada",
  "customer_phone": null,
  "note": "No onions",
  "order_items": [{ "product_id": 71, "quantity": 2 }]
}
```

Created response (`201`) or idempotent replay (`200`):

```json
{
  "outcome": "created",
  "client_request_id": "c66c8d41-e3ec-4cf4-b63e-cbae1b82fb22",
  "order": { "id": 842, "order_status": "pending", "total_amount": 250 }
}
```

Validation and authorization failures are definitive `4xx` responses with a
stable `error.code`. A `5xx` response is deliberately ambiguous to clients,
which should retry with the same `client_request_id` before claiming failure.

## Required Directus Collections

### `payments`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | integer (PK, auto-increment) | Yes | |
| `user_id` | uuid (FK -> directus_users) | Yes | User who initiated payment |
| `plan_id` | integer (FK -> subscription_plans) | Yes | Subscription plan purchased |
| `merchant_oid` | string (unique) | Yes | Unique order ID (format: `DLVR{userId}{timestamp}`) |
| `payment_amount` | integer | Yes | Amount in minor currency units (e.g. 9999 = 99.99) |
| `payment_status` | enum: `pending`, `success`, `failed` | Yes | Default: `pending` |
| `payment_type` | string (nullable) | No | e.g. `card` |
| `provider` | enum: `paytr`, `iyzico`, `stripe` | Yes | Default: `paytr` |
| `currency` | string | Yes | ISO 4217 code (e.g. `TRY`, `USD`, `EUR`) |
| `stored_card_user_token` | string (nullable) | No | User token for recurring billing |
| `stored_card_token` | string (nullable) | No | Card token for recurring billing |
| `is_recurring` | boolean | No | Default: `false` |
| `failed_reason` | string (nullable) | No | Error message from provider |
| `date_created` | timestamp | Yes | Auto-set |

### Custom fields on `directus_users`

| Field | Type | Description |
|-------|------|-------------|
| `subscription_tier` | enum: `free`, `pro` | Current subscription tier |
| `subscription_expires_at` | timestamp (nullable) | When subscription expires |
| `stored_card_user_token` | string (nullable) | Stored card user token |
| `stored_card_token` | string (nullable) | Stored card token |

### Custom fields on `subscription_plans`

| Field | Type | Description |
|-------|------|-------------|
| `price_minor` | integer | Price in minor currency units (e.g. `9999` = 99.99) |
| `currency` | string | ISO 4217 code (default: `TRY`) |

## Environment Variables

Set these on your Directus instance. Provider credentials stay provider-specific:

### PayTR

| Variable | Required | Description |
|----------|----------|-------------|
| `PAYTR_MERCHANT_ID` | Yes | Merchant ID from PayTR panel |
| `PAYTR_MERCHANT_KEY` | Yes | Merchant password (API key) |
| `PAYTR_MERCHANT_SALT` | Yes | Merchant secret key |
| `PAYTR_CALLBACK_URL` | Yes | Full URL to `/payments/callback` |
| `PAYTR_TEST_MODE` | No | `1` for test mode, `0` for production (default: `0`) |
| `PAYTR_OK_URL` | No | Full URL to `/payments/ok` |
| `PAYTR_FAIL_URL` | No | Full URL to `/payments/fail` |

### General

| Variable | Required | Description |
|----------|----------|-------------|
| `PAYMENTS_APP_URL` | No | Web app URL for redirects (default: `http://localhost:8081`) |
| `BUSINESS_ROLE_ID` | Yes | Directus role ID granted on successful payment |
| `SSO_DEFAULT_ROLE_ID` | Yes | Directus role ID restored on cancellation (shared with `sso-exchange`) |

### Marketplace order payments

| Variable | Required | Description |
|----------|----------|-------------|
| `PAYTR_ORDER_CALLBACK_URL` | Yes | Full URL to `/payments/paytr/callback` |
| `PAYTR_ORDER_OK_URL` | Yes | App URL for the verification-only redirect screen |
| `PAYTR_ORDER_FAIL_URL` | Yes | App URL for failed or abandoned hosted payment |
| `PAYTR_ORDER_TEST_MODE` | No | `1` in PayTR test mode, default `0` |
| `PAYMENT_DELIVERY_CODE_PEPPER` | Yes | Secret used to derive and hash order-specific delivery codes |
| `PAYMENT_ACCOUNT_ENCRYPTION_KEY` | Yes | Base64-encoded 32-byte AES-256-GCM key for payout IBANs |
| `MARKETPLACE_LIFECYCLE_ACTOR_ID` | Yes for automatic payouts | Delivr administrator user used by the scheduled transfer command |
| `MARKETPLACE_LIFECYCLE_CRON` | No | Marketplace hook schedule, default every minute |

Marketplace amounts are stored as integer minor units. Card data, PayTR credentials, plaintext
delivery codes, and plaintext IBANs are never persisted. Subscription rows and order-payment rows
remain separate even though they use the same provider credentials.

> **Security:** Merchant keys and salts are secrets. Never expose them client-side.

## Subscription → role model

Entitlement is carried by the user's **role**, not by a user-level policy:

- Payment succeeds → `directus_users.role` becomes `BUSINESS_ROLE_ID`, `subscription_tier` becomes `pro`
- Subscription cancelled → role reverts to `SSO_DEFAULT_ROLE_ID`, `subscription_tier` cleared

Two things this depends on:

1. **The Business role must have policies attached** (`directus_access` rows with `role = BUSINESS_ROLE_ID`).
   A role with no policies grants nothing, so the swap would be a no-op.
2. **Directus only applies role-level policies to JWT-authenticated requests.** Granting a policy
   directly to a user via `directus_access` does not work for app traffic — that approach was tried
   and reverted.

The role is baked into the access-token claims minted by `sso-exchange`, so a role change does not
affect an already-issued token. `/check-status` returns `role_updated: true` on success; the client
should call `/sso-exchange/refresh` when it sees that, otherwise the new permissions only take
effect once the access token expires (`ACCESS_TOKEN_TTL`, default 15m).

## Renewal period

A successful payment writes the period in two places:

| Target | Field | Value |
|--------|-------|-------|
| `directus_users` | `subscription_expires_at` | `max(now, current expiry) + plan.duration_days` |
| `subscriptions` (per venue) | `start_date` / `end_date` | period start kept while running, end = the new expiry |
| `subscriptions` | `last_payment_id` | the payment that bought the period |

Two rules this encodes:

1. **A renewal stacks.** Paying five days before expiry leaves 35 days, not 30. Replacing the
   expiry with `now + 30 days` silently charged early renewers for days they already owned.
2. **The period length comes from `subscription_plans.duration_days`,** not from a constant, so a
   yearly or trial plan does not need a code change.

The user record and the payment status move together in one transaction that claims the payment row
with `SELECT … FOR UPDATE WHERE payment_status = 'pending'`. Both the provider callback and the
client's `/check-status` poll reach this path for the same payment; without the claim, a stacking
renewal could be applied twice.

The `subscriptions` row is mirrored **after** that transaction commits, and its failures are logged
rather than raised. It is bookkeeping the daily sweep and the reconcile script read, while the user
record is what gates the app — a stale `venue_id` must not cost a paying customer their entitlement.
A business that pays before its venue record exists gets the user-level entitlement only; the venue
row follows on the next payment after onboarding, or from
`packages/directus-migrate/backfill-subscriptions.ts` in the delivr repo.

**Expiry is not handled here.** Downgrading a lapsed account and warning before expiry belong to the
[`subscription-lifecycle`](../subscription-lifecycle/) hook.

## Installation

### Kubernetes (ConfigMap)

The Directus pod mounts the built bundles from the `directus-extensions` ConfigMap, so the pod
needs no public internet egress. The ConfigMap lives in the infrastructure repo at
`manifests/delivery-platform/directus-extensions-configmap.yaml`.

**A source change is not live until the ConfigMap is regenerated and the pod restarts.** After
editing the extension source:

```bash
bun run build                      # regenerate dist/index.js
# then, in the infrastructure repo:
./scripts/sync-directus-extensions.sh
kubectl apply -f manifests/delivery-platform/directus-extensions-configmap.yaml
kubectl -n delivery-platform rollout restart deploy/directus
```

`EXTENSIONS_AUTO_RELOAD=false`, so `kubectl apply` alone does nothing — the restart is required.
Run `./scripts/sync-directus-extensions.sh --check` to verify the ConfigMap matches the built
bundles; it exits non-zero when they have drifted.

Commit `src/` and `dist/` together — nothing enforces the build step, and a commit that updates
only `src/` silently ships stale code.

### Manual

```bash
cd extensions/payments
bun install
bun run build
```

Copy `dist/` and `package.json` to your Directus extensions directory.

## Testing

1. Set `PAYTR_TEST_MODE=1` in Directus environment
2. Create a subscription plan with `price_minor` (e.g. `9999`) and `currency` (e.g. `TRY`)
3. Use PayTR test cards:

| Card Number | Expiry | CVV | Name |
|-------------|--------|-----|------|
| 4355 0843 5508 4358 | 12/30 | 000 | PAYTR TEST |
| 5406 6754 0667 5403 | 12/30 | 000 | PAYTR TEST |
| 9792 0303 9444 0796 | 12/30 | 000 | PAYTR TEST |

## License

MIT
