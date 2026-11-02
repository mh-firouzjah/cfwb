import type { Env } from "./env";
import { createHandshakeDecoder, type HandshakeDecoder, type ProtocolMode } from "./protocol";
import { Session, type SessionOptions, type SessionDependencies } from "./session";
import { connectTCP } from "./transport/tcp";
import { upgradeWebSocket } from "./transport/websocket";

// The path is the endpoint's first secret; a minimum length keeps it unguessable.
const ENDPOINT_PATH_PATTERN = /^\/[A-Za-z0-9_-]{16,128}$/;
const SESSION_OPTIONS: SessionOptions = { handshakeTimeoutMs: 10_000 };

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

function misconfigured(): Response {
  return new Response("Misconfigured\n", { status: 500, headers: NOT_FOUND_HEADERS });
}

interface Endpoint {
  readonly path: string;
  readonly createDecoder: () => HandshakeDecoder;
}

/**
 * Both protocols are mandatory. Throws a message naming the offending binding
 * (never its value) when a required binding is unusable.
 */
function loadEndpoints(env: Env): Record<ProtocolMode, Endpoint> {
  for (const name of ["UUID", "VL_PATH", "TR_PASSWORD", "TR_PATH"] as const) {
    if (typeof env[name] !== "string" || env[name].length === 0) throw new Error(`${name} is not configured`);
  }
  for (const name of ["VL_PATH", "TR_PATH"] as const) {
    if (!ENDPOINT_PATH_PATTERN.test(env[name])) throw new Error(`${name} is invalid`);
  }
  if (env.VL_PATH === env.TR_PATH) throw new Error("VL_PATH and TR_PATH must differ");

  const vl = (): HandshakeDecoder => createHandshakeDecoder("vl", { uuid: env.UUID });
  const tr = (): HandshakeDecoder => createHandshakeDecoder("tr", { password: env.TR_PASSWORD });
  try {
    vl();
  } catch {
    throw new Error("UUID is invalid");
  }
  try {
    tr();
  } catch {
    throw new Error("TR_PASSWORD is invalid");
  }
  return { vl: { path: env.VL_PATH, createDecoder: vl }, tr: { path: env.TR_PATH, createDecoder: tr } };
}

export function createWorker(dependencies: SessionDependencies = { connect: connectTCP }): ExportedHandler<Env> {
  return {
    async fetch(request: Request, env: Env): Promise<Response> {
      const url = new URL(request.url);
      if (request.method !== "GET" || url.protocol !== "https:") return notFound();
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return notFound();

      let endpoints: Record<ProtocolMode, Endpoint>;
      try {
        endpoints = loadEndpoints(env);
      } catch (error) {
        console.error(error instanceof Error ? error.message : "invalid configuration");
        return misconfigured();
      }

      const endpoint =
        url.pathname === endpoints.vl.path
          ? endpoints.vl
          : url.pathname === endpoints.tr.path
            ? endpoints.tr
            : undefined;
      if (endpoint === undefined) return notFound();

      return (
        upgradeWebSocket(request, (transport) => {
          new Session(transport, endpoint.createDecoder(), SESSION_OPTIONS, dependencies).start();
        }) ?? notFound()
      );
    }
  } satisfies ExportedHandler<Env>;
}

export default createWorker();
