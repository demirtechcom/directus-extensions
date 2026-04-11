# Payments Extension

Directus endpoint extension for subscription payments. Currently supports [PayTR](https://www.paytr.com) with a provider-agnostic interface ready for iyzico, Stripe, and others.

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/payments/get-token` | Required | Generate payment iframe token |
| `GET` | `/payments/check-status` | Required | Check payment status via provider API |
| `POST` | `/payments/callback` | Public | Webhook called by payment provider |
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

Response:
```json
{ "payment_status": "success" }
```

### POST /payments/callback

Called by the payment provider after payment completes. Verifies the HMAC-SHA256 hash, updates the payment record, and activates the user's subscription. Must return plain text `OK`.

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

> **Security:** Merchant keys and salts are secrets. Never expose them client-side.

## Installation

### Kubernetes (init container)

```yaml
initContainers:
  - name: fetch-extensions
    image: alpine:3
    command:
      - sh
      - -c
      - |
        mkdir -p /extensions/payments/dist
        wget -O /extensions/payments/dist/index.js \
          "https://raw.githubusercontent.com/demirtechcom/directus-extensions/main/extensions/payments/dist/index.js"
        wget -O /extensions/payments/package.json \
          "https://raw.githubusercontent.com/demirtechcom/directus-extensions/main/extensions/payments/package.json"
    volumeMounts:
      - name: extensions
        mountPath: /extensions
```

### Manual

```bash
cd extensions/payments
npm install
npm run build
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
