import { describe, expect, it } from "vitest";
import { Session, type SessionOptions, type SessionDependencies } from "../src/session";
import type { Destination, HandshakeDecoder, HandshakeResult } from "../src/protocol";
import {
  ByteStreamTransportError,
  type ByteStreamTransport,
  type SessionCloseReason,
  type UpstreamConnection
} from "../src/transport";

const OPTIONS: SessionOptions = { handshakeTimeoutMs: 1_000 };
const DESTINATION: Destination = { host: "example.net", port: 443 };
const PREFIX = Uint8Array.of(0x41, 0x42);

class TestHandshakeDecoder implements HandshakeDecoder {
  #buffer = new Uint8Array();
  #complete = false;

  push(chunk: Uint8Array): HandshakeResult {
    if (this.#complete) return { kind: "rejected", reason: "invalid_request" };
    const combined = new Uint8Array(this.#buffer.byteLength + chunk.byteLength);
    combined.set(this.#buffer);
    combined.set(chunk, this.#buffer.byteLength);
    this.#buffer = combined;

    if (combined.byteLength < 2) return { kind: "incomplete" };
    this.#complete = true;

    if (combined[0] === 0xff) return { kind: "rejected", reason: "authentication_failed" };
    if (combined[0] === 0xfe) return { kind: "rejected", reason: "unsupported_command" };
    if (combined[0] !== PREFIX[0] || combined[1] !== PREFIX[1]) {
      return { kind: "rejected", reason: "invalid_request" };
    }

    return {
      kind: "complete",
      handshake: {
        destination: DESTINATION,
        initialPayload: combined.slice(2),
        response: Uint8Array.of(0xaa, 0x55)
      }
    };
  }
}

class MemoryTransport implements ByteStreamTransport {
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;
  readonly writes: Uint8Array[] = [];
  readonly closed: Promise<void>;
  closeReason: SessionCloseReason | undefined;
  #inputEnded = false;
  #resolveClosed!: () => void;
  #controller!: ReadableStreamDefaultController<Uint8Array>;
  readonly #failWrites: boolean;

  constructor(failWrites = false) {
    this.#failWrites = failWrites;
    this.closed = new Promise((resolve) => {
      this.#resolveClosed = resolve;
    });
    this.readable = new ReadableStream<Uint8Array>({
      start: (controller) => {
        this.#controller = controller;
      }
    });
    this.writable = new WritableStream<Uint8Array>({
      write: (chunk) => {
        if (this.#failWrites) throw new ByteStreamTransportError("synthetic transport write failure");
        this.writes.push(chunk.slice());
      }
    });
  }

  send(bytes: Uint8Array): void {
    if (!this.#inputEnded && this.closeReason === undefined) {
      this.#controller.enqueue(bytes.slice());
    }
  }

  /** Ends only the client-to-session byte stream; it does not close the transport. */
  endInput(): void {
    if (this.#inputEnded) return;
    this.#inputEnded = true;
    this.#controller.close();
  }

  close(reason: SessionCloseReason): void {
    if (this.closeReason !== undefined) return;
    this.closeReason = reason;
    this.endInput();
    this.#resolveClosed();
  }
}

class MemorySocket implements UpstreamConnection {
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;
  readonly writes: Uint8Array[] = [];
  readonly #writeDelayMs: number;
  readonly #failWrites: boolean;
  #readController!: ReadableStreamDefaultController<Uint8Array>;
  #readEnded = false;
  #concurrentWrites = 0;
  #maximumConcurrentWrites = 0;
  #closeCalls = 0;
  #writeEnded = false;
  readonly #failClose: boolean;

  constructor(options: { writeDelayMs?: number; failWrites?: boolean; failClose?: boolean } = {}) {
    this.#writeDelayMs = options.writeDelayMs ?? 0;
    this.#failWrites = options.failWrites ?? false;
    this.#failClose = options.failClose ?? false;
    this.readable = new ReadableStream<Uint8Array>({
      start: (controller) => {
        this.#readController = controller;
      }
    });
    this.writable = new WritableStream<Uint8Array>({
      write: async (chunk) => {
        this.#concurrentWrites += 1;
        this.#maximumConcurrentWrites = Math.max(this.#maximumConcurrentWrites, this.#concurrentWrites);
        try {
          if (this.#writeDelayMs > 0) await new Promise((resolve) => setTimeout(resolve, this.#writeDelayMs));
          if (this.#failWrites) throw new Error("synthetic TCP write failure");
          this.writes.push(chunk.slice());
        } finally {
          this.#concurrentWrites -= 1;
        }
      },
      close: () => {
        this.#writeEnded = true;
      }
    });
  }

  get closeCalls(): number {
    return this.#closeCalls;
  }

  get maximumConcurrentWrites(): number {
    return this.#maximumConcurrentWrites;
  }

  get writeEnded(): boolean {
    return this.#writeEnded;
  }

  push(bytes: Uint8Array): void {
    if (!this.#readEnded) this.#readController.enqueue(bytes.slice());
  }

  end(): void {
    if (this.#readEnded) return;
    this.#readEnded = true;
    this.#readController.close();
  }

  failRead(error = new Error("synthetic TCP read failure")): void {
    if (this.#readEnded) return;
    this.#readEnded = true;
    this.#readController.error(error);
  }

  async close(): Promise<void> {
    this.#closeCalls += 1;
    this.end();
    if (this.#failClose) throw new Error("synthetic TCP close failure");
  }
}

async function waitFor(predicate: () => boolean, timeoutMs = 1_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("condition timed out");
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
}

function createSession(
  socket: MemorySocket,
  options: Partial<SessionOptions> = {},
  dependencyOverrides: Partial<SessionDependencies> = {},
  transport = new MemoryTransport()
) {
  let connectCalls = 0;
  const dependencies: SessionDependencies = {
    connect: async () => {
      connectCalls += 1;
      return socket;
    },
    ...dependencyOverrides
  };
  const session = new Session(transport, new TestHandshakeDecoder(), { ...OPTIONS, ...options }, dependencies);
  session.start();
  return {
    transport,
    get connectCalls() {
      return connectCalls;
    }
  };
}

describe("transport- and protocol-independent session", () => {
  it("rejects a second start without creating another session loop", () => {
    const transport = new MemoryTransport();
    const session = new Session(transport, new TestHandshakeDecoder(), OPTIONS, {
      connect: async () => new MemorySocket()
    });

    session.start();
    expect(() => session.start()).toThrow("session already started");
    transport.close("normal");
  });

  it("ends an incomplete handshake when the client input stream reaches EOF", async () => {
    const harness = createSession(new MemorySocket());
    harness.transport.send(PREFIX.subarray(0, 1));
    harness.transport.endInput();

    await waitFor(() => harness.transport.closeReason !== undefined);
    expect(harness.transport.closeReason).toBe("normal");
    expect(harness.connectCalls).toBe(0);
  });

  it("reassembles a handshake, preserves its payload and relays both stream directions", async () => {
    const socket = new MemorySocket();
    const harness = createSession(socket);
    const payload = Uint8Array.of(9, 8, 7);

    harness.transport.send(PREFIX.subarray(0, 1));
    harness.transport.send(Uint8Array.from([PREFIX[1]!, ...payload]));
    await waitFor(() => socket.writes.length === 1 && harness.transport.writes.length === 1);

    expect(harness.transport.writes[0]).toEqual(Uint8Array.of(0xaa, 0x55));
    expect(socket.writes[0]).toEqual(payload);

    socket.push(Uint8Array.of(1, 2, 3, 4));
    await waitFor(() => harness.transport.writes.length === 2);
    expect(harness.transport.writes[1]).toEqual(Uint8Array.of(1, 2, 3, 4));

    harness.transport.close("normal");
    await waitFor(() => socket.closeCalls === 1);
  });

  it.each([
    [0xff, "authentication_failed"],
    [0xfe, "unsupported_command"],
    [0xfd, "invalid_request"]
  ] as const)("closes a rejected handshake with %s", async (marker, reason) => {
    const socket = new MemorySocket();
    const harness = createSession(socket);
    harness.transport.send(Uint8Array.of(marker, 0));

    await waitFor(() => harness.transport.closeReason !== undefined);
    expect(harness.transport.closeReason).toBe(reason);
    expect(harness.connectCalls).toBe(0);
  });

  it("does not expose TCP connection errors to the transport", async () => {
    const socket = new MemorySocket();
    const harness = createSession(
      socket,
      {},
      {
        connect: async () => {
          throw new Error("private network detail");
        }
      }
    );
    harness.transport.send(PREFIX);

    await waitFor(() => harness.transport.closeReason !== undefined);
    expect(harness.transport.closeReason).toBe("tcp_failed");
  });

  it("closes an unauthenticated session at its handshake deadline", async () => {
    const harness = createSession(new MemorySocket(), { handshakeTimeoutMs: 20 });
    await waitFor(() => harness.transport.closeReason !== undefined);
    expect(harness.transport.closeReason).toBe("handshake_timeout");
    expect(harness.connectCalls).toBe(0);
  });

  it("aborts a pending TCP open when the transport closes", async () => {
    let connectSignal: AbortSignal | undefined;
    const harness = createSession(
      new MemorySocket(),
      {},
      {
        connect: async (_destination, signal) => {
          connectSignal = signal;
          return new Promise<UpstreamConnection>((_resolve, reject) => {
            signal.addEventListener("abort", () => reject(new DOMException("canceled", "AbortError")), {
              once: true
            });
          });
        }
      }
    );
    harness.transport.send(PREFIX);
    await waitFor(() => connectSignal !== undefined);
    harness.transport.close("normal");

    await waitFor(() => connectSignal?.aborted === true);
  });

  it("closes a TCP connection that resolves after its session has ended", async () => {
    let resolveConnect!: (connection: UpstreamConnection) => void;
    const socket = new MemorySocket();
    const harness = createSession(
      socket,
      {},
      {
        connect: async () =>
          new Promise<UpstreamConnection>((resolve) => {
            resolveConnect = resolve;
          })
      }
    );
    harness.transport.send(PREFIX);
    await waitFor(() => resolveConnect !== undefined);
    harness.transport.close("normal");
    resolveConnect(socket);

    await waitFor(() => socket.closeCalls === 1);
  });

  it("half-closes the TCP write direction when client input ends and continues destination output", async () => {
    const socket = new MemorySocket();
    const harness = createSession(socket);
    harness.transport.send(PREFIX);
    await waitFor(() => harness.transport.writes.length === 1);

    harness.transport.endInput();
    await waitFor(() => socket.writeEnded && !socket.writable.locked);
    expect(harness.transport.closeReason).toBeUndefined();

    socket.push(Uint8Array.of(5, 6, 7));
    await waitFor(() => harness.transport.writes.length === 2);
    expect(harness.transport.writes[1]).toEqual(Uint8Array.of(5, 6, 7));

    socket.end();
    await waitFor(() => harness.transport.closeReason === "normal");
  });

  it("keeps client input open after destination EOF until the client ends its stream", async () => {
    const socket = new MemorySocket();
    const harness = createSession(socket);
    harness.transport.send(PREFIX);
    await waitFor(() => harness.transport.writes.length === 1);

    socket.end();
    await waitFor(() => !socket.readable.locked);
    expect(harness.transport.closeReason).toBeUndefined();

    harness.transport.send(Uint8Array.of(4, 5, 6));
    await waitFor(() => socket.writes.length === 1);
    expect(socket.writes).toEqual([Uint8Array.of(4, 5, 6)]);

    harness.transport.endInput();
    await waitFor(() => harness.transport.closeReason === "normal");
  });

  it("serializes client writes and preserves order under TCP backpressure", async () => {
    const socket = new MemorySocket({ writeDelayMs: 5 });
    const harness = createSession(socket);
    harness.transport.send(PREFIX);
    await waitFor(() => harness.transport.writes.length === 1);

    harness.transport.send(Uint8Array.of(1));
    harness.transport.send(Uint8Array.of(2));
    harness.transport.send(Uint8Array.of(3));
    await waitFor(() => socket.writes.length === 3);
    expect(socket.writes).toEqual([Uint8Array.of(1), Uint8Array.of(2), Uint8Array.of(3)]);
    expect(socket.maximumConcurrentWrites).toBe(1);

    harness.transport.close("normal");
  });

  it("closes after a TCP read failure", async () => {
    const socket = new MemorySocket();
    const harness = createSession(socket);
    harness.transport.send(PREFIX);
    await waitFor(() => harness.transport.writes.length === 1);
    socket.failRead();

    await waitFor(() => harness.transport.closeReason !== undefined);
    expect(harness.transport.closeReason).toBe("tcp_failed");
  });

  it("closes when the destination writable stream rejects a client write", async () => {
    const socket = new MemorySocket({ failWrites: true });
    const harness = createSession(socket);
    harness.transport.send(PREFIX);
    await waitFor(() => harness.transport.writes.length === 1);
    harness.transport.send(Uint8Array.of(9));

    await waitFor(() => harness.transport.closeReason !== undefined);
    expect(harness.transport.closeReason).toBe("tcp_failed");
  });

  it("closes when the transport writable stream rejects destination output and releases upstream locks", async () => {
    const socket = new MemorySocket();
    const transport = new MemoryTransport(true);
    const harness = createSession(socket, {}, {}, transport);
    harness.transport.send(PREFIX);

    await waitFor(() => harness.transport.closeReason !== undefined);
    await waitFor(() => socket.closeCalls === 1 && !socket.readable.locked && !socket.writable.locked);
    expect(harness.transport.closeReason).toBe("transport_failed");
  });

  it("releases a pending upstream reader when socket close rejects after closing streams", async () => {
    const socket = new MemorySocket({ failClose: true });
    const harness = createSession(socket);
    harness.transport.send(PREFIX);
    await waitFor(() => harness.transport.writes.length === 1 && socket.readable.locked);
    harness.transport.close("normal");

    await waitFor(() => socket.closeCalls === 1 && !socket.readable.locked && !socket.writable.locked);
    expect(socket.closeCalls).toBe(1);
  });

  it("rejects invalid timeout configuration before starting", () => {
    const transport = new MemoryTransport();
    expect(
      () =>
        new Session(
          transport,
          new TestHandshakeDecoder(),
          { ...OPTIONS, handshakeTimeoutMs: 0 },
          {
            connect: async () => new MemorySocket()
          }
        )
    ).toThrow(RangeError);
  });
});
