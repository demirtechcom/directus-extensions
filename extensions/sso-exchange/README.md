# sso-exchange

Directus endpoint extension that enables native Apple/Google Sign-In for mobile apps and SSO login for web apps. Validates identity tokens directly with Apple/Google (no Keycloak or external IdP required) and returns Directus access + refresh tokens.

## Endpoints

### POST /sso-exchange — Native mobile login

Accepts an Apple or Google identity token, validates it, and returns Directus tokens.

```
POST /sso-exchange
Content-Type: application/json

{
  "token": "<Apple or Google identity token>",
  "issuer": "apple" | "google"
}
```

**Response:**

```json
{
  "data": {
    "access_token": "eyJ...",
    "refresh_token": "abc123...",
    "expires": 900000
  }
}
```

### POST /sso-exchange/refresh — Token refresh

Refreshes an expired access token using the session token.

```
POST /sso-exchange/refresh
Content-Type: application/json

{
  "refresh_token": "<session token from login>"
}
```

**Response:** Same format as login. Session token is rotated on each refresh.

### GET /sso-exchange/web-callback — Web SSO callback

Used by the Directus SSO redirect flow for web apps. After Keycloak authentication, Directus redirects here with a session cookie. The endpoint generates tokens and redirects to the web app with tokens in the URL hash fragment.

```
GET /sso-exchange/web-callback?app_url=https://your-web-app.com/auth/callback
```

**Redirects to:**

```
https://your-web-app.com/auth/callback#access_token=eyJ...&refresh_token=abc...&expires=900000
```

## How it works

### Mobile (iOS / Android)

```
User taps "Continue with Apple/Google"
  → Native SDK returns identity token
  → App calls POST /sso-exchange { token, issuer }
  → Extension verifies token with Apple JWKS / Google tokeninfo
  → Finds or creates Directus user
  → Returns Directus access + refresh tokens
```

### Web (Expo Web / React)

```
User clicks "Sign In"
  → Browser redirects to Directus SSO URL:
    /auth/login/keycloak?redirect=/sso-exchange/web-callback?app_url=...
  → Keycloak login page
  → User authenticates
  → Directus sets session cookie, redirects to /sso-exchange/web-callback
  → Extension reads session cookie, generates tokens
  → Redirects to web app with tokens in URL hash:
    https://your-app.com/auth/callback#access_token=...&refresh_token=...
  → Web app reads hash, stores tokens
```

## Environment variables

Set these in your Directus deployment:

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET` | Yes | Directus secret (already set in Directus) |
| `SSO_GOOGLE_CLIENT_ID` | For Google | Google Web Client ID for audience validation |
| `SSO_DEFAULT_ROLE_ID` | No | Directus role ID assigned to new users |
| `SSO_WEB_ALLOWED_ORIGINS` | For web | Comma-separated allowed web app origins (e.g. `http://localhost:8081,https://app.example.com`) |
| `AUTH_KEYCLOAK_REDIRECT_ALLOW_LIST` | For web | Must include the web-callback URL: `https://<DIRECTUS>/sso-exchange/web-callback` |
| `ACCESS_TOKEN_TTL` | No | Access token TTL (default: `15m`) |
| `REFRESH_TOKEN_TTL` | No | Session TTL (default: `7d`) |

## Installation

### Option 1: Kubernetes init container (recommended)

```yaml
initContainers:
  - name: fetch-extensions
    image: alpine:3
    command:
      - sh
      - -c
      - |
        mkdir -p /extensions/sso-exchange/dist
        wget -O /extensions/sso-exchange/dist/index.js \
          "https://raw.githubusercontent.com/demirtechcom/directus-extensions/main/extensions/sso-exchange/dist/index.js"
        wget -O /extensions/sso-exchange/package.json \
          "https://raw.githubusercontent.com/demirtechcom/directus-extensions/main/extensions/sso-exchange/package.json"
    volumeMounts:
      - name: extensions
        mountPath: /extensions
```

Mount the shared volume in the Directus container at `/directus/extensions`.

### Option 2: Docker volume mount

```bash
npm install
npm run build
# Mount the extension directory into /directus/extensions/sso-exchange/
```

### Option 3: Custom Directus image

```dockerfile
FROM directus/directus:11.17.0
COPY dist/index.js /directus/extensions/sso-exchange/dist/index.js
COPY package.json /directus/extensions/sso-exchange/package.json
```

## Client integration

### Mobile — Native Apple Sign-In (iOS)

```ts
import * as AppleAuthentication from "expo-apple-authentication";

const credential = await AppleAuthentication.signInAsync({
  requestedScopes: [
    AppleAuthentication.AppleAuthenticationScope.EMAIL,
    AppleAuthentication.AppleAuthenticationScope.FULL_NAME,
  ],
});

const res = await fetch(`${DIRECTUS_URL}/sso-exchange`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ token: credential.identityToken, issuer: "apple" }),
});

const { data } = await res.json();
// data.access_token, data.refresh_token, data.expires
```

### Mobile — Native Google Sign-In (Android)

```ts
import { GoogleSignin } from "@react-native-google-signin/google-signin";

const response = await GoogleSignin.signIn();
const res = await fetch(`${DIRECTUS_URL}/sso-exchange`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ token: response.data.idToken, issuer: "google" }),
});

const { data } = await res.json();
```

### Web — Directus SSO redirect (Expo Web / React)

```ts
// 1. Redirect to Directus SSO (login.tsx)
const callbackUrl = `${DIRECTUS_URL}/sso-exchange/web-callback?app_url=${encodeURIComponent(window.location.origin + "/auth/callback")}`;
const ssoUrl = `${DIRECTUS_URL}/auth/login/keycloak?redirect=${encodeURIComponent(callbackUrl)}`;
window.location.href = ssoUrl;

// 2. Handle callback (auth/callback.tsx)
const hash = window.location.hash.substring(1);
const params = new URLSearchParams(hash);
const tokens = {
  access_token: params.get("access_token"),
  refresh_token: params.get("refresh_token"),
  expires: Number(params.get("expires")),
};
// Store tokens and redirect to app
```

### Token refresh (all platforms)

```ts
const res = await fetch(`${DIRECTUS_URL}/sso-exchange/refresh`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ refresh_token: storedRefreshToken }),
});

const { data } = await res.json();
// data.access_token (new), data.refresh_token (rotated), data.expires
```

## Build

```bash
npm install
npm run build
```

## License

MIT
