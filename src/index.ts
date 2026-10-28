import { parseCredential, parseWebSocketPath } from "./auth";
import { TunnelSession, type SessionOptions } from "./websocket";

interface Env {
  readonly UUID: string;
  readonly VL_PATH: string;
  readonly TR_PASSWORD: string;
  readonly TR_PATH: string;
}

const HTTPS_PORTS = new Set(["", "443", "2053", "2083", "2087", "2096", "8443"]);
const MAX_EARLY_DATA_BYTES = 2048;
const MAX_EARLY_DATA_BASE64URL_LENGTH = Math.ceil((MAX_EARLY_DATA_BYTES * 4) / 3);

const NOT_FOUND_HEADERS = {
  "Cache-Control": "no-store",
  "Content-Type": "text/plain; charset=utf-8",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY"
};

function notFound(): Response {
  return new Response("Not Found\n", { status: 404, headers: NOT_FOUND_HEADERS });
}

function decodeWebSocketEarlyData(value: string): Uint8Array | undefined {
  if (
    value.length === 0 ||
    value.length > MAX_EARLY_DATA_BASE64URL_LENGTH ||
    value.length % 4 === 1 ||
    !/^[A-Za-z0-9_-]+$/.test(value)
  ) {
    return undefined;
  }

  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  let decoded: string;
  try {
    decoded = atob(padded);
  } catch {
    return undefined;
  }
  if (decoded.length === 0 || decoded.length > MAX_EARLY_DATA_BYTES) return undefined;

  const bytes = new Uint8Array(decoded.length);
  for (let index = 0; index < decoded.length; index += 1) {
    bytes[index] = decoded.charCodeAt(index);
  }
  // Vl version 0 is the expected first byte. Full validation remains in VlHandshakeParser.
  if (bytes[0] !== 0) return undefined;
  return bytes;
}

function sessionOptions(
  expectedHost: string,
  protocolMode: "vl" | "tr",
  trPassword: string | undefined
): SessionOptions {
  return {
    expectedHost,
    protocolMode,
    TR_PASSWORD: trPassword || undefined,
    handshakeTimeoutMs: 10_000,
    connectTimeoutMs: 10_000,
    idleTimeoutMs: 300_000
  };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== "GET" || url.protocol !== "https:" || !HTTPS_PORTS.has(url.port)) return notFound();
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return notFound();

    const credential = parseCredential(env.UUID, env.VL_PATH);
    const trPath = env.TR_PATH ? parseWebSocketPath(env.TR_PATH) : undefined;

    // Vl and Tr use separate paths during the experiment. If the paths
    // collide, fail closed instead of guessing which protocol was intended.
    if (trPath !== undefined && trPath === credential.path) return notFound();

    const isVlPath = url.pathname === credential.path;
    const isTrPath = trPath !== undefined && url.pathname === trPath;
    if (!isVlPath && !isTrPath) return notFound();
    if (isTrPath && (!env.TR_PASSWORD || new TextEncoder().encode(env.TR_PASSWORD).byteLength > 512)) {
      return notFound();
    }

    const protocolMode = isTrPath ? "tr" : "vl";

    // HTTP-level early data is supported only by the Vl path.
    const earlyDataHeader = request.headers.get("Sec-WebSocket-Protocol");
    if (protocolMode === "tr" && earlyDataHeader !== null) return notFound();
    const earlyData = earlyDataHeader === null ? undefined : decodeWebSocketEarlyData(earlyDataHeader);
    if (earlyDataHeader !== null && earlyData === undefined) return notFound();

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    const session = new TunnelSession(
      server,
      credential,
      sessionOptions(url.hostname, protocolMode, protocolMode === "tr" ? env.TR_PASSWORD : undefined)
    );
    session.start(earlyData);
    const headers = new Headers();
    if (earlyDataHeader !== null) headers.set("Sec-WebSocket-Protocol", earlyDataHeader);
    return new Response(null, { status: 101, webSocket: client, headers });
  }
} satisfies ExportedHandler<Env>;
