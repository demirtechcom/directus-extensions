# Directus Extensions

Open-source Directus extensions by [DemirTech](https://demirtech.com).

## Extensions

| Extension | Type | Description |
|-----------|------|-------------|
| [sso-exchange](extensions/sso-exchange/) | Endpoint | Native Apple & Google Sign-In for mobile apps |
| [payments](extensions/payments/) | Endpoint | Payment integration (PayTR, iyzico, Stripe) |
| [subscription-lifecycle](extensions/subscription-lifecycle/) | Hook | Daily sweep: warns before expiry, downgrades lapsed accounts |

## Usage with Kubernetes

Each extension ships a pre-built `dist/index.js`. Use an init container to download extensions at startup — no custom Directus image needed:

```yaml
initContainers:
  - name: fetch-extensions
    image: alpine:3
    command:
      - sh
      - -c
      - |
        mkdir -p /extensions/sso-exchange/dist /extensions/payments/dist /extensions/subscription-lifecycle/dist
        wget -O /extensions/sso-exchange/dist/index.js \
          "https://raw.githubusercontent.com/demirtechcom/directus-extensions/main/extensions/sso-exchange/dist/index.js"
        wget -O /extensions/sso-exchange/package.json \
          "https://raw.githubusercontent.com/demirtechcom/directus-extensions/main/extensions/sso-exchange/package.json"
        wget -O /extensions/payments/dist/index.js \
          "https://raw.githubusercontent.com/demirtechcom/directus-extensions/main/extensions/payments/dist/index.js"
        wget -O /extensions/payments/package.json \
          "https://raw.githubusercontent.com/demirtechcom/directus-extensions/main/extensions/payments/package.json"
        wget -O /extensions/subscription-lifecycle/dist/index.js \
          "https://raw.githubusercontent.com/demirtechcom/directus-extensions/main/extensions/subscription-lifecycle/dist/index.js"
        wget -O /extensions/subscription-lifecycle/package.json \
          "https://raw.githubusercontent.com/demirtechcom/directus-extensions/main/extensions/subscription-lifecycle/package.json"
    volumeMounts:
      - name: extensions
        mountPath: /extensions
```

Mount the volume in the Directus container at `/directus/extensions`.

> **DemirTech deployments do not use this.** The `delivery-platform` cluster mounts the bundles from
> a ConfigMap instead, so the pod needs no public internet egress. A source change is not live until
> the ConfigMap is regenerated and the pod restarted — see
> [extensions/payments/README.md](extensions/payments/) and
> `infastructure/scripts/sync-directus-extensions.sh`.

## Development

```bash
cd extensions/<name>
npm install
npm run build    # builds dist/index.js
npm run dev      # watch mode
```

## License

MIT
