# Directus Extensions

Open-source Directus extensions by [DemirTech](https://demirtech.com).

## Extensions

| Extension | Type | Description |
|-----------|------|-------------|
| [sso-exchange](extensions/sso-exchange/) | Endpoint | Native Apple & Google Sign-In for mobile apps |

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
        mkdir -p /extensions/sso-exchange/dist
        wget -O /extensions/sso-exchange/dist/index.js \
          "https://raw.githubusercontent.com/demirtechcom/directus-extensions/main/extensions/sso-exchange/dist/index.js"
        wget -O /extensions/sso-exchange/package.json \
          "https://raw.githubusercontent.com/demirtechcom/directus-extensions/main/extensions/sso-exchange/package.json"
    volumeMounts:
      - name: extensions
        mountPath: /extensions
```

Mount the volume in the Directus container at `/directus/extensions`.

## Development

```bash
cd extensions/<name>
npm install
npm run build    # builds dist/index.js
npm run dev      # watch mode
```

## License

MIT
