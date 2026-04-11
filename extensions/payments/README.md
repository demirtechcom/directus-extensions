# PayTR Payment Extension

Directus endpoint extension for [PayTR](https://www.paytr.com) payment integration. Handles credit card subscription payments via PayTR's iFrame API with webhook callbacks.

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/paytr/get-token` | Required | Generate PayTR iframe token for payment |
| `POST` | `/paytr/callback` | Public | Webhook endpoint called by PayTR after payment |

### POST /paytr/get-token

Request (authenticated):
```json
{ "plan_id": 4 }
```

Response:
```json
{
  "token": "28cc613c3d7633cfa4ed...",
  "merchant_oid": "DLVR-6f265eca-1749212345678"
}
```

Use the token to render the PayTR payment iframe:
```html
<iframe src="https://www.paytr.com/odeme/guvenli/{token}"></iframe>
```

### POST /paytr/callback

Called by PayTR after payment completes. Verifies the HMAC-SHA256 hash, updates the payment record, and activates the user's subscription on success. Must return plain text `OK`.

## Required Directus Collections

### `paytr_payments`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | integer (PK, auto-increment) | Yes | |
| `user_id` | uuid (FK -> directus_users) | Yes | User who initiated payment |
| `plan_id` | integer (FK -> subscription_plans) | Yes | Subscription plan purchased |
| `merchant_oid` | string (unique) | Yes | Unique order ID (format: `DLVR-{userId}-{timestamp}`) |
| `payment_amount` | integer | Yes | Amount in kurus (TRY * 100) |
| `payment_status` | enum: `pending`, `success`, `failed` | Yes | Default: `pending` |
| `payment_type` | string (nullable) | No | Set by PayTR callback (e.g. `card`) |
| `utoken` | string (nullable) | No | User token for recurring billing |
| `ctoken` | string (nullable) | No | Card token for recurring billing |
| `is_recurring` | boolean | No | Default: `false` |
| `failed_reason` | string (nullable) | No | Error message from PayTR |
| `date_created` | timestamp | Yes | Auto-set |

### Custom fields on `directus_users`

| Field | Type | Description |
|-------|------|-------------|
| `subscription_tier` | enum: `free`, `pro` | Current subscription tier |
| `subscription_expires_at` | timestamp (nullable) | When subscription expires |
| `paytr_utoken` | string (nullable) | Stored card user token |
| `paytr_ctoken` | string (nullable) | Stored card token |

### Custom field on `subscription_plans`

| Field | Type | Description |
|-------|------|-------------|
| `paytr_price_kurus` | integer | Price in kurus (e.g. `9999` = 99.99 TRY) |

## Environment Variables

Set these on your Directus instance:

| Variable | Required | Description |
|----------|----------|-------------|
| `PAYTR_MERCHANT_ID` | Yes | Merchant ID from PayTR panel |
| `PAYTR_MERCHANT_KEY` | Yes | Merchant password (API key) |
| `PAYTR_MERCHANT_SALT` | Yes | Merchant secret key |
| `PAYTR_CALLBACK_URL` | Yes | Full URL to `/paytr/callback` (e.g. `https://cms.example.com/paytr/callback`) |
| `PAYTR_TEST_MODE` | No | `1` for test mode, `0` for production (default: `0`) |
| `PAYTR_OK_URL` | No | Redirect URL after successful payment |
| `PAYTR_FAIL_URL` | No | Redirect URL after failed payment |

> **Security:** `PAYTR_MERCHANT_KEY` and `PAYTR_MERCHANT_SALT` are secrets. Never expose them client-side. The extension reads them from `env` on the server.

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
        mkdir -p /extensions/paytr/dist
        wget -O /extensions/paytr/dist/index.js \
          "https://raw.githubusercontent.com/demirtechcom/directus-extensions/main/extensions/paytr/dist/index.js"
        wget -O /extensions/paytr/package.json \
          "https://raw.githubusercontent.com/demirtechcom/directus-extensions/main/extensions/paytr/package.json"
    volumeMounts:
      - name: extensions
        mountPath: /extensions
```

### Manual

```bash
cd extensions/paytr
npm install
npm run build
```

Copy the `dist/` folder and `package.json` to your Directus extensions directory.

## Testing

1. Set `PAYTR_TEST_MODE=1` in Directus environment
2. Create a subscription plan with `paytr_price_kurus` set (e.g. `9999`)
3. Use PayTR test cards:

| Card Number | Expiry | CVV | Name |
|-------------|--------|-----|------|
| 4355 0843 5508 4358 | 12/30 | 000 | PAYTR TEST |
| 5406 6754 0667 5403 | 12/30 | 000 | PAYTR TEST |
| 9792 0303 9444 0796 | 12/30 | 000 | PAYTR TEST |

## License

MIT
