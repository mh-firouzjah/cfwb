import { connect } from "cloudflare:sockets";
import type { Destination } from "../contracts";
import type { UpstreamConnection } from "./index";

const CONNECT_TIMEOUT_MS = 10_000;
const MAX_CONNECT_ATTEMPTS = 2;

const PLATFORM_DENIAL_MESSAGES = [
  "request failed, cannot connect to the specified address",
  "tcp loop detected",
  "connections to port 25 are prohibited"
] as const;

function abortError(signal: AbortSignal): Error {
  const reason: unknown = signal.reason;
  return reason instanceof Error && reason.name !== "AbortError" ? reason : new Error("connection canceled");
}

function isPlatformDenied(error: unknown): boolean {
  const message = (error instanceof Error ? error.message : String(error)).toLowerCase();
  return PLATFORM_DENIAL_MESSAGES.some((part) => message.includes(part));
}

async function closeSocketQuietly(socket: Socket): Promise<void> {
  try {
    await socket.close();
  } catch {
    // Cleanup must not replace the connection failure.
  }
}

/** Opens a TCP socket through the runtime, retrying only ordinary connection failures. */
export async function connectTCP(destination: Destination, signal: AbortSignal): Promise<UpstreamConnection> {
  for (let attempt = 0; attempt < MAX_CONNECT_ATTEMPTS; attempt += 1) {
    if (signal.aborted) throw abortError(signal);

    try {
      const socket = connect({ hostname: destination.host, port: destination.port }, { allowHalfOpen: true });
      void socket.closed.catch(() => undefined);
      await waitForSocketOpen(socket, signal);
      return socket;
    } catch (error) {
      if (signal.aborted || isPlatformDenied(error) || attempt + 1 >= MAX_CONNECT_ATTEMPTS) throw error;
    }
  }

  throw new Error("TCP connection failed");
}

/** Waits for the runtime open result and closes the socket on timeout, abort, or failure. */
export async function waitForSocketOpen(
  socket: Socket,
  signal: AbortSignal,
  timeoutMs = CONNECT_TIMEOUT_MS
): Promise<void> {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) throw new RangeError("connect timeout must be positive");
  if (signal.aborted) {
    void closeSocketQuietly(socket);
    throw abortError(signal);
  }

  await new Promise<void>((resolve, reject) => {
    let settled = false;
    let timeoutId: ReturnType<typeof setTimeout> | undefined;
    let onAbort: (() => void) | undefined;

    const cleanup = (): void => {
      if (timeoutId !== undefined) clearTimeout(timeoutId);
      if (onAbort !== undefined) signal.removeEventListener("abort", onAbort);
    };

    const succeed = (): void => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve();
    };

    const fail = (error: unknown): void => {
      if (settled) return;
      settled = true;
      cleanup();
      void closeSocketQuietly(socket);
      reject(error);
    };

    onAbort = (): void => fail(abortError(signal));
    signal.addEventListener("abort", onAbort, { once: true });
    timeoutId = setTimeout(() => fail(new Error("TCP connection timed out")), timeoutMs);
    void socket.opened.then(succeed, fail);

    // Cover an abort between the initial check and listener registration.
    if (signal.aborted) onAbort();
  });
}
