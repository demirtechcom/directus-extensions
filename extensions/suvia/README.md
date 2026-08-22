# `suvia` Directus extension

The half of Suvia that cannot live on the device: which reminder slots exist today, whether a
photo counts as proof, how many snoozes are left, and what the leaderboard shows.

A **bundle** with two entries:

| Entry | Type | What it does |
| --- | --- | --- |
| `suvia` | endpoint | Mounted at `/suvia`. Planning, challenge transitions, photo verification, leaderboard, entitlement |
| `suvia-purge` | hook | Hourly job deleting proof photos 24h after upload |

It depends on `directus/migrations/0002_functions.sql` being applied — every route here is a thin,
authenticated wrapper over a plpgsql function — and, for the two paid routes, on
`0006_entitlement.sql`. Auth comes from `req.accountability.user`, which Directus fills in from the
verified access token; **no route reads a user id from a request body**, and nothing in
`0002_functions.sql` should be reachable any other way. The one exception is
`/revenuecat-webhook`, which has no Directus session to read — see [Entitlement](#entitlement).

## Endpoints

| Method | Path | Body / query | Returns |
| --- | --- | --- | --- |
| POST | `/suvia/plan-day` | `{ tz }` | `{ count }` — slots created, 0 if already planned |
| POST | `/suvia/challenges/:id/snooze` | — | `{ snoozed }` — false when the budget is spent |
| POST | `/suvia/challenges/:id/resolve` | `{ photo, confidence, reason, amount_ml }` | `{ resolved }` |
| POST | `/suvia/verify-water-photo` | `{ photo_base64, locale }` | `{ is_water, confidence, reason, model, photo }` — **premium**, `402 PREMIUM_REQUIRED` otherwise |
| POST | `/suvia/water-logs` | `{ photo, amount_ml }` | `{ id }` — a verified log with no challenge behind it |
| GET | `/suvia/leaderboard` | `?day=YYYY-MM-DD` | ranked rows, top 100 — **premium**, `402 PREMIUM_REQUIRED` otherwise. **503** naming `0003_views.sql` when the `suvia_leaderboard_daily` view is missing, rather than a 500 carrying the Postgres error |
| POST | `/suvia/revenuecat-webhook` | RevenueCat's `{ api_version, event }` | `{ received: true, matched }` — **not** session-authenticated, see below |

Verification and resolution are **two calls**, as in v1. Verify returns a verdict the app shows
the user — including a deliberately kind rejection message — and only an approved verdict leads
to a resolve. Collapsing them would remove the screen where a rejected photo is explained.

`POST /suvia/water-logs` exists because the client may only create *manual* water logs: a
photo-backed, `ai_verified` row is evidence, and evidence the client can write is evidence it can
forge. On the challenge path that row is written by `suvia_resolve_challenge`. This is the other
path — the user tapped "+" of their own accord and the photo passed — and the verdict is not taken
from the request. `/verify-water-photo` records it on the file, and this route reads it back. The
client can create files but not update them, which is what makes that trustworthy.

Account deletion is **not** here: it reuses `POST /sso-exchange/delete-account`, which also has
to clear the Directus user itself.

## Entitlement

The design, the columns and the event→effect table live in
[`directus/README.md`](../../README.md#entitlement). What is specific to this bundle:

- **The gate is one call, `select public.suvia_is_entitled(?)`, and neither route restates the
  predicate.** It sits immediately after the `401` check and before anything else, because
  `/verify-water-photo` is the route that spends money per request: decode, upload, Anthropic. A
  refused caller must cost nothing, and that ordering is what
  `src/__tests__/entitlement.test.ts` asserts — the free-user case fails if the vision spy, the
  upload spy or `getSchema` is touched at all.
- Until `0006_entitlement.sql` is applied, both routes answer **`503`** naming the file — the same
  shape as the leaderboard's missing view. Not `402`: sending a paying user to the store because
  nobody ran a migration hides the problem from the only person who can fix it.
- **`/revenuecat-webhook` is the only route not authenticated by `req.accountability`.** RevenueCat
  calls it server-to-server, so it compares the raw `Authorization` header against
  `REVENUECAT_WEBHOOK_SECRET` with `timingSafeEqual`, before reading the body and before any query.
  If that variable is unset the route rejects everything and the extension says so at boot: unlike
  the Anthropic key, an unset secret here must never mean accept-all.
- **Retries and misordering are handled in the statement, not in the handler.** One guarded
  `update … where "user" = ? and (subscription_event_at is null or subscription_event_at <= ?)`, so
  a redelivery re-applies identical values and a stale event matches no row. Anything this route
  cannot apply — an unknown `app_user_id`, an anonymous `$RCAnonymousID:…`, a malformed envelope, a
  purchase whose entitlement id this server does not map — still answers **`200`** and logs. A
  non-2xx would only make RevenueCat repeat a request no retry can fix.
- **`matched` in the response means "this event changed a profile row".** An ignored
  `CANCELLATION`, a stale event and an unknown user all read `false`; only RevenueCat and the log
  ever see it.
## Environment

| Variable | Required | Purpose |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | yes | The vision calls. Store as a Kubernetes secret, never in the ConfigMap |
| `REVENUECAT_WEBHOOK_SECRET` | yes | The shared secret RevenueCat sends as the whole `Authorization` header (RevenueCat dashboard → Integrations → Webhooks → *Authorization header value*). A Kubernetes secret, never the ConfigMap. **Unset means `POST /suvia/revenuecat-webhook` rejects every call**, which is the safe failure but a silent one: subscriptions stop being mirrored into `suvia_profiles`, so new subscribers keep hitting the `402` on the paid routes. The boot warning is the only signal |
| `SUVIA_PHOTO_FOLDER` | yes | Directus folder id for proof photos. **Without it the purge job refuses to run** — on a shared instance, "every file older than 24 hours" would include another product's files. It must NOT be the folder the client's upload permission allows: the client is scoped to the avatar folder so it can never write into the one being swept, and the extension writes here on the user's behalf with admin raised |
| `STORAGE_LOCATIONS` | inherited | Already set on the instance; the first entry is where photos are written |

## Build and deploy

```bash
cd directus/extensions/suvia
npm install
npm run build          # -> dist/api.js + dist/app.js
bun run test           # pg error predicates, plus the entitlement gate and webhook
```

`bun run test` is not in CI. Every job in `.github/workflows/ci.yml` delegates to
`demirtechcom/ci`, which has no `directus` check and where the bun toolchain already lives — that
is the one place worth adding it, and until someone does, these tests run by hand or via the
pre-commit hook.

Deployment follows the same pattern as `sso-exchange`: an `initContainer` in
`manifests/general/directus.yaml` `wget`s each bundle from **`raw.githubusercontent.com`, from
the `main` branch of `demirtechcom/directus-extensions`**, into an `emptyDir` at pod start.

Two consequences worth knowing before you plan a release:

- **The deployed version is whatever is on `main`, not whatever is tagged.** Merging is the
  deploy; a pod restart is what picks it up. There is no ConfigMap to regenerate.
- **A rollback is a revert on `main`.** Restarting the pod re-fetches, so restarting alone will
  not take you back to a previous build.

Which means this bundle has to live in `demirtechcom/directus-extensions` alongside `sso-exchange`
to be deployable at all — it is built here, but the `dist/` that runs is the one on that repo's
`main`. Keep the two in step or the instance runs an older Suvia than this repo describes.

**Operational steps — run these yourself, they change cluster state:**

```bash
# 1. Publish the built bundle to demirtechcom/directus-extensions main
#    (extensions/suvia/dist/api.js + package.json, the paths the initContainer fetches)

# 2. Add the fetch to the initContainer in manifests/general/directus.yaml, mirroring
#    the sso-exchange block

# 3. Create the Anthropic key and the RevenueCat webhook secret in the general namespace.
#    Both in one secret because both are needed by the same container; the webhook value has to
#    match the Authorization header configured in the RevenueCat dashboard byte for byte.
kubectl -n general create secret generic suvia-extension \
  --from-literal=ANTHROPIC_API_KEY='...' \
  --from-literal=REVENUECAT_WEBHOOK_SECRET='...' \
  --dry-run=client -o yaml | kubectl apply -f -

# 4. Add SUVIA_PHOTO_FOLDER and the secret ref to the deployment env, then
kubectl -n general rollout restart deployment/directus

# 5. Point the RevenueCat webhook at https://cms.demirtech.com/suvia/revenuecat-webhook with that
#    same Authorization value, and send a test event. It must answer 200; a 401 means the two
#    strings differ, and RevenueCat will keep retrying until they do not.
```

## Verification

Nothing here has been run against a live Directus. Before trusting it:

1. `npm run build` — the bundle compiles.
2. Against a local Directus with the migrations applied: `POST /suvia/plan-day` with a real user
   token twice, confirm the second returns `count: 0`.
3. `POST /suvia/verify-water-photo` with a real photo of a glass and with a photo of something
   else; confirm the verdicts and that both photos land in `directus_files`.
4. Cross-user probe: resolve user A's challenge with user B's token and confirm
   `resolved: false` — the check is inside the SQL function, so this is the test that proves it.
5. Set the system clock forward or insert an old `uploaded_on` and confirm the purge deletes
   proof photos in `SUVIA_PHOTO_FOLDER` and nothing outside it.
6. The gate, with a **free** profile: `POST /suvia/verify-water-photo` must answer `402`
   `PREMIUM_REQUIRED`, and `directus_files` must gain **no** row — that empty folder is the
   assertion, since a gate that ran too late would look identical in the response. Then set
   `subscription_tier = 'premium', subscription_expires_at = now() + interval '1 day'` and confirm
   both it and `GET /suvia/leaderboard` succeed.
7. Webhook auth: send the RevenueCat test event with no `Authorization` header, with a wrong value,
   and with a value of the right length but the wrong bytes. All three must answer `401` and leave
   `suvia_profiles` untouched.
8. Webhook idempotency and ordering, easiest with `curl` and a hand-written envelope:
   - the same `INITIAL_PURCHASE` twice → both `200`, `subscription_*` identical after each;
   - an `EXPIRATION` whose `event_timestamp_ms` is **older** than the purchase already applied →
     `200 { matched: false }` and the tier must still be `premium`. This is the failure the guard
     exists for, and it is the one that is invisible in production;
   - a `CANCELLATION` → `200`, and nothing in `suvia_profiles` moves at all.
