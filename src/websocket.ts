import { authenticateUser, type Credential } from "./auth";
import { resolvePublicDNS } from "./dns";
import {
  DestinationPolicyError,
  resolveAndValidateDestination,
  type DestinationPolicy,
  type DNSResolver,
  type ResolvedDestination
} from "./policy";
import { TrHandshakeParser, TrProtocolError } from "./protocol/tr";
import { buildVlResponseHeader, VlHandshakeParser, VlProtocolError, type VlDestination } from "./protocol/vl";
import { connectTCP, TCPConnectionTimeoutError } from "./tcp";

const MAX_QUEUED_CLIENT_BYTES = 1024 * 1024;
const WEBSOCKET_SEND_CHUNK_BYTES = 64 * 1024;
const MAX_WEBSOCKET_CLOSE_REASON_BYTES = 123;
const MAX_DIAGNOSTIC_MESSAGES = 16;

export interface SessionOptions {
  readonly expectedHost: string;
  readonly protocolMode: "vl" | "tr";
  readonly handshakeTimeoutMs: number;
  readonly connectTimeoutMs: number;
  readonly idleTimeoutMs: number;
  readonly TR_PASSWORD?: string;
}

export interface TunnelSessionDependencies {
  readonly resolveDNS: DNSResolver;
  readonly connect: (
    destination: ResolvedDestination,
    timeoutMilliseconds: number,
    signal?: AbortSignal
  ) => Promise<Socket>;
}

const DEFAULT_DEPENDENCIES: TunnelSessionDependencies = {
  resolveDNS: resolvePublicDNS,
  connect: connectTCP
};

const CLOSE_REASON = {
  authenticationFailed: "authentication failed",
  invalidRequest: "invalid request",
  unsupportedCommand: "TCP command required",
  destinationBlocked: "private or reserved destination blocked",
  cloudflareAddressBlocked: "Cloudflare-owned destination blocked",
  invalidDestination: "invalid destination address",
  invalidDomain: "invalid destination name",
  selfDestination: "destination is this Worker",
  portBlocked: "destination port 25 is unavailable",
  dnsFailed: "DNS lookup failed",
  dnsTimeout: "DNS lookup timed out",
  tcpFailed: "TCP connection failed",
  connectTimeout: "TCP connection timed out",
  handshakeTimeout: "handshake timed out",
  idleTimeout: "connection idle timeout",
  websocketFailed: "WebSocket transport failed",
  binaryRequired: "binary frames required",
  queueExceeded: "pending client data limit exceeded"
} as const;

function messageLength(data: unknown): number | undefined {
  if (data instanceof ArrayBuffer) return data.byteLength;
  if (ArrayBuffer.isView(data)) return data.byteLength;
  if (data instanceof Blob) return data.size;
  return undefined;
}

async function asBytes(data: unknown): Promise<Uint8Array | undefined> {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);

  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength));
  }

  if (data instanceof Blob) {
    return new Uint8Array(await data.arrayBuffer());
  }

  return undefined;
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function reciprocalClose(event: CloseEvent): { readonly code: number; readonly reason?: string } {
  const receivedCodeIsSafe =
    event.code === 1000 ||
    (event.code >= 1001 && event.code <= 1014 && ![1004, 1005, 1006].includes(event.code)) ||
    (event.code >= 3000 && event.code <= 4999);

  if (!receivedCodeIsSafe) return { code: 1000 };

  const reason =
    new TextEncoder().encode(event.reason).byteLength <= MAX_WEBSOCKET_CLOSE_REASON_BYTES ? event.reason : undefined;

  return reason === undefined ? { code: event.code } : { code: event.code, reason };
}

export class TunnelSession {
  readonly #webSocket: WebSocket;
  readonly #credential: Credential;
  readonly #options: SessionOptions;
  readonly #policy: DestinationPolicy;
  readonly #dependencies: TunnelSessionDependencies;
  readonly #parser = new VlHandshakeParser();
  readonly #trParser: TrHandshakeParser | undefined;
  readonly #protocol: "vl" | "tr";
  readonly #handshakeTimer: ReturnType<typeof setTimeout>;

  #protocolLogged = false;
  #trHandshakeStarted = false;

  #idleTimer: ReturnType<typeof setTimeout>;
  #socket: Socket | undefined;
  #writer: WritableStreamDefaultWriter<Uint8Array> | undefined;
  #dnsAbortController: AbortController | undefined;
  #dnsTimer: ReturnType<typeof setTimeout> | undefined;
  #connectAbortController: AbortController | undefined;

  #messageChain: Promise<void> = Promise.resolve();
  #queuedClientBytes = 0;

  #receivedMessages = 0;
  #receivedClientBytes = 0;

  #sentDestinationMessages = 0;
  #sentDestinationBytes = 0;

  #authenticated = false;
  #closed = false;
  #responseSent = false;

  constructor(
    webSocket: WebSocket,
    credential: Credential,
    options: SessionOptions,
    dependencies: TunnelSessionDependencies = DEFAULT_DEPENDENCIES
  ) {
    this.#webSocket = webSocket;
    this.#credential = credential;
    this.#options = options;
    this.#dependencies = dependencies;
    this.#protocol = options.protocolMode;
    if (options.protocolMode === "tr" && !options.TR_PASSWORD) {
      throw new Error("Tr mode requires a password");
    }
    this.#trParser =
      options.protocolMode === "tr" && options.TR_PASSWORD ? new TrHandshakeParser(options.TR_PASSWORD) : undefined;
    this.#policy = { expectedHost: options.expectedHost };

    this.#handshakeTimer = setTimeout(
      () =>
        this.#requestClose(
          1008,
          `${CLOSE_REASON.handshakeTimeout} (frames=${this.#receivedMessages}, bytes=${this.#receivedClientBytes})`
        ),
      options.handshakeTimeoutMs
    );

    this.#idleTimer = setTimeout(() => this.#requestClose(1000, CLOSE_REASON.idleTimeout), options.idleTimeoutMs);
  }

  start(initialData?: Uint8Array): void {
    this.#webSocket.binaryType = "arraybuffer";
    this.#webSocket.accept({ allowHalfOpen: true });

    this.#webSocket.addEventListener("message", (event) => {
      this.#enqueueMessage(event.data);
    });

    this.#webSocket.addEventListener("close", (event) => {
      const reciprocal = reciprocalClose(event);
      this.#requestClose(reciprocal.code, reciprocal.reason);
    });

    this.#webSocket.addEventListener("error", () => {
      this.#requestClose(1011, CLOSE_REASON.websocketFailed);
    });

    // HTTP-level early data is accepted only on the VL endpoint.
    if (initialData !== undefined && initialData.byteLength > 0) {
      if (this.#protocol !== "vl") {
        this.#requestClose(1002, CLOSE_REASON.invalidRequest);
        return;
      }
      this.#enqueueMessage(initialData, false);
    }
  }

  #touch(): void {
    clearTimeout(this.#idleTimer);

    this.#idleTimer = setTimeout(() => this.#requestClose(1000, CLOSE_REASON.idleTimeout), this.#options.idleTimeoutMs);
  }

  #enqueueMessage(data: unknown, isWebSocketFrame = true): void {
    if (this.#closed) return;

    const byteLength = messageLength(data);

    if (byteLength === undefined) {
      this.#requestClose(1003, CLOSE_REASON.binaryRequired);
      return;
    }

    if (isWebSocketFrame) {
      this.#receivedMessages += 1;
    }

    this.#receivedClientBytes += byteLength;

    // Log sizes and counters only; never log payload contents.
    if (isWebSocketFrame && this.#receivedMessages <= MAX_DIAGNOSTIC_MESSAGES) {
      if (process.env.NODE_ENV !== "production")
        console.log("[diag] WebSocket frame received", {
          frame: this.#receivedMessages,
          authenticated: this.#authenticated,
          bytes: byteLength,
          totalBytes: this.#receivedClientBytes
        });
    } else if (!isWebSocketFrame) {
      if (process.env.NODE_ENV !== "production")
        console.log("[diag] WebSocket early data received", {
          bytes: byteLength,
          totalBytes: this.#receivedClientBytes
        });
    }

    if (
      (typeof data === "string" && data.length === 0) ||
      (data instanceof ArrayBuffer && data.byteLength === 0) ||
      (ArrayBuffer.isView(data) && data.byteLength === 0)
    ) {
      return;
    }
    this.#queuedClientBytes += byteLength;

    if (this.#queuedClientBytes > MAX_QUEUED_CLIENT_BYTES) {
      this.#requestClose(1009, CLOSE_REASON.queueExceeded);
      return;
    }

    this.#messageChain = this.#messageChain
      .then(async () => {
        const bytes = await asBytes(data);

        if (bytes === undefined) {
          this.#requestClose(1003, CLOSE_REASON.binaryRequired);
          return;
        }

        await this.#handleClientBytes(bytes);
      })
      .catch((error: unknown) => this.#handleFailure(error))
      .finally(() => {
        this.#queuedClientBytes -= byteLength;
      });
  }

  async #handleClientBytes(bytes: Uint8Array): Promise<void> {
    if (this.#closed) return;

    this.#touch();

    if (bytes.byteLength === 0) return;

    // Protocol identity is fixed by the endpoint path, never inferred from
    // payload bytes. This keeps requests on the Vl and Tr paths isolated.
    if (!this.#protocolLogged) {
      this.#protocolLogged = true;
      if (process.env.NODE_ENV !== "production")
        console.log("[diag] inbound protocol selected", { protocol: this.#protocol });
    }

    // After the handshake has completed, all bytes are raw TCP payload for
    // either protocol; protocol parsing must never run a second time.
    if (this.#writer !== undefined) {
      if (process.env.NODE_ENV !== "production")
        console.log("[diag] client payload forwarding", {
          protocol: this.#protocol,
          bytes: bytes.byteLength
        });

      await this.#writer.write(bytes);

      if (process.env.NODE_ENV !== "production")
        console.log("[diag] client payload forwarded", {
          protocol: this.#protocol,
          bytes: bytes.byteLength
        });

      return;
    }

    // The Tr password digest is exactly 56 ASCII hex bytes. Reject a
    // mismatched protocol immediately rather than waiting for a full header.
    if (this.#protocol === "tr" && !this.#trHandshakeStarted) {
      this.#trHandshakeStarted = true;
      const firstByte = bytes[0]!;
      const isHexByte = (firstByte >= 0x30 && firstByte <= 0x39) || (firstByte >= 0x61 && firstByte <= 0x66);
      if (!isHexByte) {
        this.#requestClose(1002, CLOSE_REASON.invalidRequest);
        return;
      }
    }

    let destinationRequest: VlDestination;
    let initialPayload: Uint8Array;

    if (this.#protocol === "tr") {
      let parsed;

      try {
        parsed = this.#trParser!.push(bytes);
      } catch (error) {
        if (error instanceof TrProtocolError) {
          if (error.code === "authentication_failed") {
            this.#requestClose(1008, CLOSE_REASON.authenticationFailed);
          } else if (error.code === "unsupported_command") {
            this.#requestClose(1008, CLOSE_REASON.unsupportedCommand);
          } else {
            this.#requestClose(1002, CLOSE_REASON.invalidRequest);
          }
          return;
        }

        throw error;
      }

      if (parsed === undefined) return;

      destinationRequest = parsed.destination;
      initialPayload = parsed.initialPayload;
      this.#authenticated = true;

      if (process.env.NODE_ENV !== "production")
        console.log("[diag] Tr request parsed", {
          destination: destinationRequest.host,
          port: destinationRequest.port,
          initialPayloadBytes: initialPayload.byteLength
        });
      if (process.env.NODE_ENV !== "production") console.log("[diag] Tr password authentication succeeded");
    } else {
      let parsed;

      try {
        parsed = this.#parser.push(bytes);
      } catch (error) {
        if (error instanceof VlProtocolError) {
          if (error.code === "unsupported_command") {
            this.#requestClose(1008, CLOSE_REASON.unsupportedCommand);
            return;
          }

          this.#requestClose(1002, CLOSE_REASON.invalidRequest);
          return;
        }

        throw error;
      }

      if (parsed === undefined) return;

      if (process.env.NODE_ENV !== "production")
        console.log("[diag] Vl request parsed", {
          destination: parsed.request.destination.host,
          port: parsed.request.destination.port,
          initialPayloadBytes: parsed.initialPayload.byteLength
        });

      if (!authenticateUser(parsed.request.userId, this.#credential.uuid)) {
        if (process.env.NODE_ENV !== "production") console.log("[diag] Vl authentication failed");
        this.#requestClose(1008, CLOSE_REASON.authenticationFailed);
        return;
      }

      this.#authenticated = true;
      destinationRequest = parsed.request.destination;
      initialPayload = parsed.initialPayload;
      if (process.env.NODE_ENV !== "production") console.log("[diag] Vl authentication succeeded");
    }

    clearTimeout(this.#handshakeTimer);

    const dnsController = destinationRequest.type === "domain" ? new AbortController() : undefined;

    let dnsTimer: ReturnType<typeof setTimeout> | undefined;

    if (dnsController !== undefined) {
      this.#dnsAbortController = dnsController;

      dnsTimer = setTimeout(() => {
        if (this.#dnsAbortController === dnsController) {
          this.#requestClose(1011, CLOSE_REASON.dnsTimeout);
        }
      }, this.#options.connectTimeoutMs);

      this.#dnsTimer = dnsTimer;
    }

    let destination: ResolvedDestination;

    try {
      destination = await resolveAndValidateDestination(
        destinationRequest,
        this.#policy,
        this.#dependencies.resolveDNS,
        dnsController?.signal
      );
    } catch (error) {
      if (error instanceof DestinationPolicyError) {
        this.#closeForPolicyError(error);
      } else {
        this.#requestClose(1011, CLOSE_REASON.dnsFailed);
      }

      return;
    } finally {
      dnsController?.abort();

      if (dnsTimer !== undefined) {
        clearTimeout(dnsTimer);
      }

      if (this.#dnsAbortController === dnsController) {
        this.#dnsAbortController = undefined;
      }

      if (this.#dnsTimer === dnsTimer) {
        this.#dnsTimer = undefined;
      }
    }

    if (this.#closed) return;

    if (process.env.NODE_ENV !== "production")
      console.log("[diag] destination resolved", {
        protocol: this.#protocol,
        host: destination.hostname,
        port: destination.port
      });

    const connectController = new AbortController();
    this.#connectAbortController = connectController;

    let socket: Socket;

    try {
      socket = await this.#dependencies.connect(destination, this.#options.connectTimeoutMs, connectController.signal);
    } catch (error) {
      const reason = error instanceof TCPConnectionTimeoutError ? CLOSE_REASON.connectTimeout : CLOSE_REASON.tcpFailed;

      this.#requestClose(1011, reason);
      return;
    } finally {
      if (this.#connectAbortController === connectController) {
        this.#connectAbortController = undefined;
      }
    }

    if (process.env.NODE_ENV !== "production")
      console.log("[diag] destination TCP connected", {
        protocol: this.#protocol,
        host: destination.hostname,
        port: destination.port
      });

    if (this.#closed) {
      await socket.close();
      return;
    }

    this.#socket = socket;
    this.#writer = socket.writable.getWriter();

    this.#sendResponseHeader();

    if (initialPayload.byteLength > 0) {
      if (process.env.NODE_ENV !== "production")
        console.log("[diag] initial client payload forwarding", {
          protocol: this.#protocol,
          bytes: initialPayload.byteLength
        });

      await this.#writer.write(initialPayload);

      if (process.env.NODE_ENV !== "production")
        console.log("[diag] initial client payload forwarded", {
          protocol: this.#protocol,
          bytes: initialPayload.byteLength
        });
    }

    void this.#pumpDestination(socket, destination).catch(() => {
      this.#requestClose(1011, CLOSE_REASON.tcpFailed);
    });
  }

  #sendResponseHeader(): void {
    if (this.#closed || this.#protocol !== "vl" || this.#responseSent) return;

    this.#responseSent = true;
    this.#webSocket.send(buildVlResponseHeader());
  }

  async #sendDestinationBytes(bytes: Uint8Array): Promise<void> {
    for (let offset = 0; offset < bytes.byteLength && !this.#closed; offset += WEBSOCKET_SEND_CHUNK_BYTES) {
      const chunk = bytes.subarray(offset, offset + WEBSOCKET_SEND_CHUNK_BYTES);

      this.#webSocket.send(chunk);

      this.#sentDestinationMessages += 1;
      this.#sentDestinationBytes += chunk.byteLength;

      if (this.#sentDestinationMessages <= MAX_DIAGNOSTIC_MESSAGES) {
        if (process.env.NODE_ENV !== "production")
          console.log("[diag] destination WebSocket send", {
            message: this.#sentDestinationMessages,
            bytes: chunk.byteLength,
            totalBytes: this.#sentDestinationBytes
          });
      }

      // The server-side WebSocket API has no bufferedAmount. Yield between
      // bounded sends to allow the runtime to drain its transport queue.
      await delay(0);
    }
  }

  async #pumpDestination(socket: Socket, destination: ResolvedDestination): Promise<void> {
    const reader = socket.readable.getReader();
    let readCount = 0;

    try {
      while (!this.#closed) {
        const result = await reader.read();
        readCount += 1;

        if (readCount <= MAX_DIAGNOSTIC_MESSAGES) {
          if (process.env.NODE_ENV !== "production")
            console.log("[diag] destination read", {
              read: readCount,
              host: destination.hostname,
              port: destination.port,
              done: result.done,
              bytes: result.value?.byteLength ?? 0
            });
        }

        if (result.done) {
          // The destination has closed its readable half. Keep the
          // client-to-destination direction open until client close or idle timeout.
          return;
        }

        this.#touch();

        await this.#sendDestinationBytes(result.value);
      }
    } finally {
      reader.releaseLock();
    }
  }

  #requestClose(code?: number, reason?: string): void {
    if (this.#closed) return;

    if (process.env.NODE_ENV !== "production")
      console.log("[diag] session closing", {
        code,
        reason,
        authenticated: this.#authenticated,
        responseSent: this.#responseSent,
        tcpConnected: this.#socket !== undefined,
        receivedFrames: this.#receivedMessages,
        receivedClientBytes: this.#receivedClientBytes,
        sentDestinationMessages: this.#sentDestinationMessages,
        sentDestinationBytes: this.#sentDestinationBytes
      });

    this.#closed = true;

    clearTimeout(this.#handshakeTimer);
    clearTimeout(this.#idleTimer);

    const dnsAbortController = this.#dnsAbortController;
    this.#dnsAbortController = undefined;

    if (this.#dnsTimer !== undefined) {
      clearTimeout(this.#dnsTimer);
      this.#dnsTimer = undefined;
    }

    dnsAbortController?.abort();

    const connectAbortController = this.#connectAbortController;
    this.#connectAbortController = undefined;

    connectAbortController?.abort();

    if (code !== undefined) {
      try {
        this.#webSocket.close(code, reason);
      } catch {
        // Cleanup must continue if the WebSocket is already closing.
      }
    }

    void this.#cleanup();
  }

  #closeForPolicyError(error: DestinationPolicyError): void {
    let reason: string;

    switch (error.code) {
      case "port_not_allowed":
        reason = CLOSE_REASON.portBlocked;
        break;

      case "self_destination":
        reason = CLOSE_REASON.selfDestination;
        break;

      case "invalid_domain":
        reason = CLOSE_REASON.invalidDomain;
        break;

      case "invalid_address":
        reason = CLOSE_REASON.invalidDestination;
        break;

      case "cloudflare_address":
        reason = CLOSE_REASON.cloudflareAddressBlocked;
        break;

      case "dns_resolution_failed":
        reason = CLOSE_REASON.dnsFailed;
        break;

      default:
        reason = CLOSE_REASON.destinationBlocked;
    }

    this.#requestClose(1008, reason);
  }

  #handleFailure(error: unknown): void {
    if (error instanceof DestinationPolicyError) {
      this.#closeForPolicyError(error);
      return;
    }

    this.#requestClose(
      this.#authenticated ? 1011 : 1002,
      this.#authenticated ? CLOSE_REASON.tcpFailed : CLOSE_REASON.invalidRequest
    );
  }

  async #cleanup(): Promise<void> {
    const writer = this.#writer;
    this.#writer = undefined;

    const socket = this.#socket;
    this.#socket = undefined;

    // Start the socket close immediately so a backpressured writer.close()
    // cannot indefinitely delay the release of the underlying socket.
    let socketClose = Promise.resolve();

    if (socket !== undefined) {
      try {
        socketClose = socket.close().catch(() => undefined);
      } catch {
        // A synchronous close failure leaves no additional close operation.
      }
    }

    if (writer !== undefined) {
      try {
        await writer.close();
      } catch {
        // Socket shutdown races are expected during cancellation.
      }

      try {
        writer.releaseLock();
      } catch {
        // The stream may already have released its lock after an error.
      }
    }

    await socketClose;
  }
}
