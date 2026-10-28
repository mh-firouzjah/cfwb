import { connect } from "cloudflare:sockets";
import type { ResolvedDestination } from "./policy";

export class TCPConnectionTimeoutError extends Error {
  constructor() {
    super("TCP connection timed out");
    this.name = "TCPConnectionTimeoutError";
  }
}

function timeout<T>(milliseconds: number, value: T): { promise: Promise<T>; cancel: () => void } {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const promise = new Promise<T>((resolve) => {
    timer = setTimeout(() => resolve(value), milliseconds);
  });
  return {
    promise,
    cancel: () => {
      if (timer !== undefined) clearTimeout(timer);
    }
  };
}

export async function connectTCP(
  destination: ResolvedDestination,
  timeoutMilliseconds: number,
  signal?: AbortSignal
): Promise<Socket> {
  const socket = connect({ hostname: destination.hostname, port: destination.port }, { allowHalfOpen: true });
  return await waitForSocketOpen(socket, timeoutMilliseconds, signal);
}

// Kept separate from connect() so timeout and cleanup behavior can be tested
// in workerd without replacing the cloudflare:sockets module.
export async function waitForSocketOpen(
  socket: Socket,
  timeoutMilliseconds: number,
  signal?: AbortSignal
): Promise<Socket> {
  if (!Number.isSafeInteger(timeoutMilliseconds) || timeoutMilliseconds <= 0) {
    try {
      await socket.close();
    } catch {
      // The configuration error remains the useful failure.
    }
    throw new Error("connection timeout is invalid");
  }
  const deadline = timeout(timeoutMilliseconds, "timeout" as const);
  let abortListener: (() => void) | undefined;
  const canceled = new Promise<"canceled">((resolve) => {
    if (signal === undefined) return;
    if (signal.aborted) {
      resolve("canceled");
      return;
    }
    abortListener = () => resolve("canceled");
    signal.addEventListener("abort", abortListener, { once: true });
  });
  try {
    const result = await Promise.race([socket.opened.then(() => "opened" as const), deadline.promise, canceled]);
    if (result === "canceled") throw new Error("connection canceled");
    if (result !== "opened") throw new TCPConnectionTimeoutError();
    return socket;
  } catch (error) {
    try {
      await socket.close();
    } catch {
      // The original connection error is more useful to the authenticated client.
    }
    throw error;
  } finally {
    deadline.cancel();
    if (abortListener !== undefined) signal?.removeEventListener("abort", abortListener);
  }
}
