# WebSocket-to-TCP Worker

This Worker accepts the version-0 WebSocket protocol and relays TCP to public
destinations.
It uses Cloudflare's Workers TCP sockets API and does not implement UDP, Mux, or
early data.

## Configure and deploy

The Worker uses only two secrets:

```sh
npx wrangler secret put UUID
npx wrangler secret put WS_PATH
npm run deploy
```

`UUID` must be a canonical UUID. `WS_PATH` must be a slash followed by 16–128
letters, digits, underscores, or hyphens. Keep both secret. The path is the
WebSocket endpoint; requests to other paths receive a generic 404.

`workers_dev` is enabled, so no custom domain or expected-host setting is
required. For local development, provide the same two values through Wrangler's
local secret mechanism before running `npm run dev`.

## Destination policy

The Worker accepts HTTPS WebSocket connections on ports `443`, `2053`, `2083`,
`2087`, `2096`, and `8443`; other inbound ports are rejected. Outbound TCP
permits any valid port except port 25, which the Workers TCP API blocks.
Private, loopback, link-local, reserved, Cloudflare-owned, and configured
resolver IP ranges are rejected.
Domain names are resolved before connecting, and every returned address must
pass the same policy, except that Cloudflare-owned answers are skipped when a
domain also has a public non-Cloudflare answer. The Worker selects the first
reachable public answer. Destinations resolving only to Cloudflare-owned IPs
remain blocked because Workers TCP egress cannot connect to those ranges. The
centralized range list is in
`src/data/cloudflare-ranges.json`. Special-purpose ranges follow the
[IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry) and
[IANA IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry)
registries, including NAT64 translation and SRv6 ranges that are not covered by
the basic private-network blocks.

Handshake, connection, and idle deadlines are fixed in source to bound stuck
requests and release inactive sockets; they are not deployment variables.
Worker observability is disabled in `wrangler.jsonc`.
Each active tunnel holds a Worker request and TCP socket. This Worker does not
enforce a global per-client connection quota or rate limit, so keep both
secrets private. Cloudflare runtime updates can interrupt long-lived
connections; configure clients to reconnect automatically.

## Manual client configuration

Use these values in the client:

- **Address / server / SNI / TLS host:** the deployed `*.workers.dev` hostname.
- **Port:** try `443` first. If it is unavailable on your network, try
  `2053`, `2083`, `2087`, `2096`, or `8443`.
- **Transport:** WebSocket over TLS.
- **WebSocket path:** the exact `WS_PATH` secret.
- **User ID:** the exact `UUID` secret.
- **Protocol version:** `0` (TCP).

The destination hostname or IP and destination port are selected by the client
for each connection, subject to the Worker policy above.
The listed HTTPS ports apply only to the client-to-Worker connection; outbound
TCP destinations may use any valid port except `25`.

## Development

```sh
npm ci
npm run dev
npm test
npm run typecheck
npm run deploy
```
