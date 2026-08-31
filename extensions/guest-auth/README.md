# guest-auth

Directus endpoint extension that creates a restricted anonymous customer account and returns the
same access/refresh token shape used by the shipped Delivr clients.

## Endpoint

```http
POST /guest-auth
Content-Type: application/json

{ "guest_id": "550e8400-e29b-41d4-a716-446655440000" }
```

Successful response:

```json
{
  "data": {
    "access_token": "eyJ...",
    "refresh_token": "session-token",
    "expires": 900000
  }
}
```

`guest_id` is treated as an opaque bearer identifier. Repeating a request with the same UUID reuses
the same Directus user instead of creating another one. The endpoint never issues a session for an
archived guest.

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET` | Yes | Directus JWT secret |
| `GUEST_ROLE_ID` | Recommended | Restricted customer role for guest users |
| `SSO_DEFAULT_ROLE_ID` | Fallback | Used only when `GUEST_ROLE_ID` is unset |
| `ACCESS_TOKEN_TTL` | No | Access token TTL (default: `15m`) |
| `REFRESH_TOKEN_TTL` | No | Refresh session TTL (default: `7d`) |
| `GUEST_AUTH_RATE_LIMIT_MAX` | No | Requests allowed per IP/window (default: `20`) |
| `GUEST_AUTH_RATE_LIMIT_WINDOW` | No | Rate-limit window (default: `15m`) |

The configured guest role must exist and must not have Directus administrator access. Deployment
fails closed when the role or `SECRET` is missing.

## Development

```bash
bun install
bun test
bun run build
```

The built `dist/index.js` is committed because DemirTech deployments generate Directus extension
ConfigMaps from this repository. After merging, regenerate the instance ConfigMap and restart the
Directus deployment; merging source alone does not make the endpoint live.
