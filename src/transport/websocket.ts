import { ByteStreamTransportError, type ByteStreamTransport, type SessionCloseReason } from "./index";

const MAX_WEBSOCKET_CLOSE_REASON_BYTES = 123;

interface WebSocketCloseInfo {
  readonly code: number;
  readonly reason: string;
}

const CLOSE_INFO: Record<SessionCloseReason, WebSocketCloseInfo> = {
  normal: { code: 1000, reason: "normal closure" },
  invalid_request: { code: 1002, reason: "invalid request" },
  authentication_failed: { code: 1008, reason: "authentication failed" },
  unsupported_command: { code: 1008, reason: "TCP command required" },
  tcp_failed: { code: 1011, reason: "TCP connection failed" },
  handshake_timeout: { code: 1008, reason: "handshake timed out" },
  transport_failed: { code: 1011, reason: "WebSocket transport failed" }
};

function asBytes(data: unknown): Uint8Array | undefined {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  return undefined;
}

function reciprocalClose(event: CloseEvent): WebSocketCloseInfo {
  const safeCode =
    event.code === 1000 ||
    (event.code >= 1001 && event.code <= 1014 && ![1004, 1005, 1006].includes(event.code)) ||
    (event.code >= 3000 && event.code <= 4999);
  if (!safeCode) return { code: 1000, reason: "normal closure" };

  const reason =
    new TextEncoder().encode(event.reason).byteLength <= MAX_WEBSOCKET_CLOSE_REASON_BYTES
      ? event.reason
      : "normal closure";
  return { code: event.code, reason };
}

/** Decodes the Base64URL early-data token with the standard API; undefined when malformed or empty. */
function decodeEarlyData(value: string): Uint8Array | undefined {
  try {
    const bytes = Uint8Array.fromBase64(value, { alphabet: "base64url" });
    return bytes.byteLength > 0 ? bytes : undefined;
  } catch {
    return undefined;
  }
}

/** Adapts Cloudflare's event-based WebSocket API to byte streams; no buffering policy is added. */
export class WebSocketTransport implements ByteStreamTransport {
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;

  readonly #socket: WebSocket;
  #controller: ReadableStreamDefaultController<Uint8Array> | undefined;
  #closed = false;
  readonly closed: Promise<void>;
  #resolveClosed!: () => void;

  readonly #onMessage = (event: MessageEvent): void => this.#enqueueMessage(event.data);
  readonly #onClose = (event: CloseEvent): void => {
    const closeInfo = reciprocalClose(event);
    this.#finish(closeInfo);
  };
  readonly #onError = (): void => this.#fail(1011, "WebSocket transport failed");

  constructor(socket: WebSocket, initialData?: Uint8Array) {
    this.#socket = socket;
    this.closed = new Promise((resolve) => {
      this.#resolveClosed = resolve;
    });

    this.readable = new ReadableStream<Uint8Array>({
      start: (controller) => {
        this.#controller = controller;
        socket.binaryType = "arraybuffer";
        socket.addEventListener("message", this.#onMessage);
        socket.addEventListener("close", this.#onClose);
        socket.addEventListener("error", this.#onError);
        socket.accept({ allowHalfOpen: true });
        if (initialData !== undefined && initialData.byteLength > 0) this.#enqueueBytes(initialData);
      },
      cancel: () => this.close("normal")
    });

    this.writable = new WritableStream<Uint8Array>({
      write: (chunk) => this.#write(chunk),
      // WebSocket has no directional EOF; upstream EOF closes this transport.
      close: () => this.close("normal"),
      abort: () => this.close("transport_failed")
    });
  }

  close(reason: SessionCloseReason): void {
    this.#finish(CLOSE_INFO[reason]);
  }

  #enqueueMessage(data: unknown): void {
    if (this.#closed) return;

    const bytes = asBytes(data);
    if (bytes === undefined) {
      this.#fail(1003, "binary frames required");
      return;
    }

    this.#enqueueBytes(bytes);
  }

  #enqueueBytes(bytes: Uint8Array): void {
    if (this.#closed || bytes.byteLength === 0) return;

    const controller = this.#controller;
    if (controller === undefined) {
      this.#fail(1011, "WebSocket transport failed");
      return;
    }

    try {
      controller.enqueue(bytes);
    } catch {
      this.#fail(1011, "WebSocket transport failed");
    }
  }

  #write(bytes: Uint8Array): void {
    if (this.#closed) throw new ByteStreamTransportError("WebSocket transport is closed");

    try {
      this.#socket.send(bytes);
    } catch {
      this.#fail(1011, "WebSocket transport failed");
      throw new ByteStreamTransportError("WebSocket send failed");
    }
  }

  #fail(code: number, reason: string): void {
    this.#finish({ code, reason }, new ByteStreamTransportError(reason));
  }

  #finish(closeInfo: WebSocketCloseInfo, error?: Error): void {
    if (this.#closed) return;
    this.#closed = true;

    this.#socket.removeEventListener("message", this.#onMessage);
    this.#socket.removeEventListener("close", this.#onClose);
    this.#socket.removeEventListener("error", this.#onError);

    try {
      this.#socket.close(closeInfo.code, closeInfo.reason);
    } catch {
      // The WebSocket may already be closing.
    }

    try {
      if (error === undefined) this.#controller?.close();
      else this.#controller?.error(error);
    } catch {
      // The readable stream may already be closed or errored.
    } finally {
      this.#resolveClosed();
    }
  }
}

/** Validates WebSocket early data, creates the pair and hands over the stream adapter. */
export function upgradeWebSocket(
  request: Request,
  startSession: (transport: ByteStreamTransport) => void
): Response | undefined {
  const earlyDataHeader = request.headers.get("Sec-WebSocket-Protocol");
  const earlyData = earlyDataHeader === null ? undefined : decodeEarlyData(earlyDataHeader);
  if (earlyDataHeader !== null && earlyData === undefined) return undefined;

  const pair = new WebSocketPair();
  const transport = new WebSocketTransport(pair[1], earlyData);
  try {
    startSession(transport);
  } catch (error) {
    transport.close("transport_failed");
    throw error;
  }

  const headers = new Headers();
  if (earlyDataHeader !== null) headers.set("Sec-WebSocket-Protocol", earlyDataHeader);
  return new Response(null, { status: 101, webSocket: pair[0], headers });
}
