# cfwb

Single-user Cloudflare Worker that accepts VLESS (`vl`) and Trojan (`tr`) over
WebSocket+TLS and relays one TCP stream per connection through
`cloudflare:sockets`.

## Layout

```
src/
├── index.ts          request checks, configuration and routing
├── env.ts            binding types
├── contracts.ts      shared destination type
├── session.ts        protocol- and transport-neutral session lifecycle
├── protocol/         vl.ts, tr.ts parsers; wire.ts helpers; index.ts adapter
└── transport/        shared contracts, WebSocket and TCP adapters
```

## Configure and deploy

Both protocols are mandatory; the Worker answers every request with a 500 and
logs the offending binding name (never its value) until all four are valid.

```sh
npx wrangler secret put UUID
npx wrangler secret put VL_PATH
npx wrangler secret put TR_PASSWORD
npx wrangler secret put TR_PATH
npm run deploy
```

Paths are `/` plus 16–128 of `A-Za-z0-9_-` and must differ. Keep all four secret.

## What the Worker does and does not enforce

- Enforced here: GET + `Upgrade: websocket` over HTTPS, secret path, protocol
  authentication, TCP command only, binary frames only, handshake deadline
  (10 s, unauthenticated peers only).
- Left to Cloudflare: inbound port availability, outbound address restrictions
  (including private and Cloudflare-owned addresses), port 25 restrictions and
  DNS resolution. The Worker adds no destination blacklist, DNS resolver,
  custom queue, chunking, aggregate size cap or idle timer.
- Each TCP opening attempt has a 10-second deadline. One retry is allowed for
  ordinary failures (20 seconds maximum across two attempts); documented runtime
  rejections are not retried. A closed client
  connection cancels the pending open and closes that session's resources.
- WebSocket early data (`Sec-WebSocket-Protocol`, Base64URL) is accepted on both
  paths without a Worker-defined size cap. The client controls its own limit;
  both sample sing-box outbounds currently use 2048 bytes.
- There is no destination filtering: an authenticated client chooses any host
  and port. Do not share the secrets.

## Development

```sh
npm ci
npm run check   # format, lint, typecheck and tests
npm run dev
```
