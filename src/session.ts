import type { HandshakeDecoder, HandshakeResult, ParsedHandshake } from "./protocol";
import {
  ByteStreamTransportError,
  type ByteStreamTransport,
  type Connector,
  type SessionCloseReason,
  type UpstreamConnection
} from "./transport";

export interface SessionOptions {
  /** Bounds how long an unauthenticated peer may hold the connection before a complete handshake. */
  readonly handshakeTimeoutMs: number;
}

export interface SessionDependencies {
  readonly connect: Connector;
}

/** Coordinates one protocol-neutral, transport-neutral TCP session lifecycle. */
export class Session {
  readonly #transport: ByteStreamTransport;
  readonly #decoder: HandshakeDecoder;
  readonly #options: SessionOptions;
  readonly #dependencies: SessionDependencies;

  #started = false;
  #closed = false;
  #clientInputEnded = false;
  #destinationEnded = false;
  #handshakeTimer: ReturnType<typeof setTimeout> | undefined;
  #connectAbortController: AbortController | undefined;
  #pipeAbortController: AbortController | undefined;
  #connection: UpstreamConnection | undefined;
  #clientPipe: Promise<void> | undefined;
  #destinationPipe: Promise<void> | undefined;

  constructor(
    transport: ByteStreamTransport,
    decoder: HandshakeDecoder,
    options: SessionOptions,
    dependencies: SessionDependencies
  ) {
    if (!Number.isSafeInteger(options.handshakeTimeoutMs) || options.handshakeTimeoutMs <= 0) {
      throw new RangeError("handshake timeout must be a positive safe integer");
    }
    this.#transport = transport;
    this.#decoder = decoder;
    this.#options = options;
    this.#dependencies = dependencies;
  }

  start(): void {
    if (this.#started) throw new Error("session already started");
    this.#started = true;
    void this.#transport.closed.then(() => this.#requestClose("normal"));
    this.#handshakeTimer = setTimeout(() => this.#requestClose("handshake_timeout"), this.#options.handshakeTimeoutMs);
    void this.#run();
  }

  async #run(): Promise<void> {
    const reader = this.#transport.readable.getReader();
    let startPipes = false;

    try {
      while (!this.#closed) {
        const result = await reader.read();
        if (result.done) {
          this.#requestClose("normal");
          return;
        }

        if (result.value.byteLength === 0) continue;

        let handshake: HandshakeResult;
        try {
          handshake = this.#decoder.push(result.value);
        } catch {
          this.#requestClose("invalid_request");
          return;
        }

        if (handshake.kind === "incomplete") continue;
        if (handshake.kind === "rejected") {
          this.#requestClose(handshake.reason);
          return;
        }

        if (this.#handshakeTimer !== undefined) clearTimeout(this.#handshakeTimer);
        this.#handshakeTimer = undefined;

        if (!(await this.#establish(handshake.handshake))) return;
        startPipes = true;
        return;
      }
    } catch {
      if (!this.#closed) this.#requestClose("transport_failed");
    } finally {
      reader.releaseLock();
      if (startPipes && !this.#closed) this.#startPipes();
    }
  }

  async #establish(handshake: ParsedHandshake): Promise<boolean> {
    const connectController = new AbortController();
    this.#connectAbortController = connectController;
    let connection: UpstreamConnection;
    try {
      connection = await this.#dependencies.connect(handshake.destination, connectController.signal);
    } catch {
      if (!this.#closed) this.#requestClose("tcp_failed");
      return false;
    } finally {
      if (this.#connectAbortController === connectController) this.#connectAbortController = undefined;
    }

    if (this.#closed) {
      try {
        await connection.close();
      } catch {
        // A late connection must be closed without reviving the session.
      }
      return false;
    }

    this.#connection = connection;

    if (handshake.response !== undefined && handshake.response.byteLength > 0) {
      try {
        await writeStreamChunk(this.#transport.writable, handshake.response);
      } catch {
        this.#requestClose("transport_failed");
        return false;
      }
    }

    if (handshake.initialPayload.byteLength > 0) {
      try {
        await writeStreamChunk(connection.writable, handshake.initialPayload);
      } catch {
        this.#requestClose("tcp_failed");
        return false;
      }
    }

    return !this.#closed;
  }

  #startPipes(): void {
    const connection = this.#connection;
    if (connection === undefined || this.#closed) return;

    const abortController = new AbortController();
    this.#pipeAbortController = abortController;
    const options = {
      signal: abortController.signal,
      preventAbort: true,
      preventCancel: true
    };

    try {
      this.#clientPipe = this.#transport.readable.pipeTo(connection.writable, options);
    } catch {
      this.#requestClose("tcp_failed");
      return;
    }

    void this.#clientPipe.then(
      () => {
        if (this.#closed) return;
        this.#clientInputEnded = true;
        this.#maybeClose();
      },
      (error: unknown) => {
        if (!this.#closed) {
          this.#requestClose(error instanceof ByteStreamTransportError ? "transport_failed" : "tcp_failed");
        }
      }
    );

    try {
      this.#destinationPipe = connection.readable.pipeTo(this.#transport.writable, {
        signal: abortController.signal,
        preventAbort: true
      });
    } catch {
      this.#requestClose("transport_failed");
      return;
    }

    void this.#destinationPipe.then(
      () => {
        if (this.#closed) return;
        this.#destinationEnded = true;
        this.#maybeClose();
      },
      (error: unknown) => {
        if (!this.#closed) {
          this.#requestClose(error instanceof ByteStreamTransportError ? "transport_failed" : "tcp_failed");
        }
      }
    );
  }

  #maybeClose(): void {
    if (this.#clientInputEnded && this.#destinationEnded) this.#requestClose("normal");
  }

  #requestClose(reason: SessionCloseReason): void {
    if (this.#closed) return;
    this.#closed = true;

    if (this.#handshakeTimer !== undefined) clearTimeout(this.#handshakeTimer);
    this.#handshakeTimer = undefined;

    this.#pipeAbortController?.abort();
    this.#pipeAbortController = undefined;
    this.#connectAbortController?.abort();
    this.#connectAbortController = undefined;

    try {
      this.#transport.close(reason);
    } catch {
      // Cleanup must continue when the transport has already closed.
    }

    void this.#cleanup();
  }

  async #cleanup(): Promise<void> {
    const connection = this.#connection;
    this.#connection = undefined;
    const clientPipe = this.#clientPipe;
    const destinationPipe = this.#destinationPipe;
    this.#clientPipe = undefined;
    this.#destinationPipe = undefined;

    let connectionClose = Promise.resolve();
    if (connection !== undefined) {
      try {
        connectionClose = connection.close().catch(() => undefined);
      } catch {
        // A synchronous close failure does not prevent pipe cleanup.
      }
    }

    const pipes = [clientPipe, destinationPipe].filter((pipe): pipe is Promise<void> => pipe !== undefined);
    await Promise.allSettled(pipes);
    await connectionClose;
  }
}

async function writeStreamChunk(stream: WritableStream<Uint8Array>, chunk: Uint8Array): Promise<void> {
  const writer = stream.getWriter();
  try {
    await writer.write(chunk);
  } finally {
    writer.releaseLock();
  }
}
