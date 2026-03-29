# sso-exchange

Directus endpoint extension that enables native Apple and Google Sign-In for mobile apps. Validates identity tokens directly with Apple/Google (no Keycloak or external IdP required) and returns Directus access + refresh tokens.

## Endpoint

```
POST /sso-exchange
Content-Type: application/json

{
  "token": "<Apple or Google identity token>",
  "issuer": "apple" | "google"
}
```

### Response

```json
{
  "data": {
    "access_token": "eyJ...",
    "refresh_token": "abc123...",
    "expires": 900000
  }
}
```

## How it works

1. Receives a native identity token from the mobile app
2. **Apple**: Verifies the JWT signature against Apple's JWKS (`https://appleid.apple.com/auth/keys`)
3. **Google**: Validates the token via Google's tokeninfo endpoint with audience check
4. Finds an existing Directus user by email, or creates a new one
5. Signs a Directus-compatible JWT and creates a session
6. Returns access token + refresh token to the app

## Environment variables

Set these in your Directus deployment:

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET` | Yes | Directus secret (already set in Directus) |
| `SSO_GOOGLE_CLIENT_ID` | Yes | Google Web Client ID for audience validation |
| `SSO_DEFAULT_ROLE_ID` | No | Directus role ID assigned to new users |
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

## Mobile app integration

```ts
// Native Apple Sign-In
const credential = await AppleAuthentication.signInAsync({ ... });
const res = await fetch(`${DIRECTUS_URL}/sso-exchange`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ token: credential.identityToken, issuer: "apple" }),
});
const { data } = await res.json();
// data.access_token, data.refresh_token, data.expires

// Native Google Sign-In
const response = await GoogleSignin.signIn();
const res = await fetch(`${DIRECTUS_URL}/sso-exchange`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ token: response.data.idToken, issuer: "google" }),
});
```

## Build

```bash
npm install
npm run build
```

## License

MIT
