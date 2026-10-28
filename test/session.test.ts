import { describe, expect, it } from "vitest";
import type { Credential } from "../src/auth";
import { TunnelSession, type SessionOptions, type TunnelSessionDependencies } from "../src/websocket";
import { requestBytes, VALID_UUID_BYTES } from "./fixtures";
import { trRequest } from "./trojan-fixtures";

const credential: Credential = {
  uuid: VALID_UUID_BYTES,
  path: "/unit-test-path-0001"
};

const options: SessionOptions = {
  expectedHost: "edge.example.com",
  protocolMode: "vl",
  handshakeTimeoutMs: 100,
  connectTimeoutMs: 100,
  idleTimeoutMs: 2_000
};

class MemorySocket implements Socket {
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;
  readonly opened = Promise.resolve<SocketInfo>({ remoteAddress: "93.184.216.34:443" });
  readonly upgraded = false;
  readonly secureTransport = "off" as const;
  readonly writes: Uint8Array[] = [];
  readonly closed: Promise<void>;
  concurrentWrites = 0;
  maximumConcurrentWrites = 0;
  closeCalls = 0;
  #controller!: ReadableStreamDefaultController<Uint8Array>;
  #resolveClosed!: () => void;
  #ended = false;
  readonly #writeDelayMs: number;

  constructor(writeDelayMs = 0) {
    this.#writeDelayMs = writeDelayMs;
    this.closed = new Promise((resolve) => {
      this.#resolveClosed = resolve;
    });
    this.readable = new ReadableStream<Uint8Array>({
      start: (controller) => {
        this.#controller = controller;
      }
    });
    this.writable = new WritableStream<Uint8Array>({
      write: async (chunk) => {
        this.concurrentWrites += 1;
        this.maximumConcurrentWrites = Math.max(this.maximumConcurrentWrites, this.concurrentWrites);
        if (this.#writeDelayMs > 0) await new Promise((resolve) => setTimeout(resolve, this.#writeDelayMs));
        this.writes.push(chunk.slice());
        this.concurrentWrites -= 1;
      }
    });
  }

  push(bytes: Uint8Array): void {
    this.#controller.enqueue(bytes);
  }

  end(): void {
    if (this.#ended) return;
    this.#ended = true;
    this.#controller.close();
    this.#resolveClosed();
  }

  async close(): Promise<void> {
    this.closeCalls += 1;
    this.end();
  }

  startTls(): Socket {
    return this;
  }
}

async function binaryData(data: unknown): Promise<Uint8Array> {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (data instanceof Blob) return new Uint8Array(await data.arrayBuffer());
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength));
  }
  throw new Error("expected binary message");
}

function nextMessage(socket: WebSocket): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const onClose = (event: CloseEvent) => reject(new Error(`socket closed before message: ${event.code}`));
    socket.addEventListener("close", onClose, { once: true });
    socket.addEventListener(
      "message",
      (event) => {
        socket.removeEventListener("close", onClose);
        void binaryData(event.data).then(resolve, reject);
      },
      { once: true }
    );
  });
}

function nextMessages(socket: WebSocket, count: number): Promise<Uint8Array[]> {
  return new Promise((resolve, reject) => {
    const messages: Uint8Array[] = [];
    let conversionChain = Promise.resolve();

    const cleanup = () => {
      socket.removeEventListener("message", onMessage);
      socket.removeEventListener("close", onClose);
    };
    const onClose = (event: CloseEvent) => {
      cleanup();
      reject(new Error(`socket closed after ${messages.length} of ${count} messages: ${event.code}`));
    };
    const onMessage = (event: MessageEvent) => {
      conversionChain = conversionChain
        .then(async () => {
          messages.push(await binaryData(event.data));
          if (messages.length === count) {
            cleanup();
            resolve(messages);
          }
        })
        .catch((error: unknown) => {
          cleanup();
          reject(error);
        });
    };

    socket.addEventListener("message", onMessage);
    socket.addEventListener("close", onClose, { once: true });
  });
}

function nextClose(socket: WebSocket): Promise<CloseEvent> {
  return new Promise((resolve) => socket.addEventListener("close", resolve, { once: true }));
}

async function waitFor(predicate: () => boolean, timeoutMs = 500): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("condition timed out");
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
}

function validSessionRequest(payload = new Uint8Array()): Uint8Array {
  return requestBytes({
    address: Uint8Array.from([11, ...new TextEncoder().encode("example.com")]),
    payload
  });
}

function createSession(
  socket: MemorySocket,
  overrides: Partial<SessionOptions> = {},
  dependencyOverrides: Partial<TunnelSessionDependencies> = {},
  initialData?: Uint8Array
) {
  const pair = new WebSocketPair();
  let connectCalls = 0;
  const dependencies: TunnelSessionDependencies = {
    resolveDNS: async () => ["93.184.216.34"],
    connect: async () => {
      connectCalls += 1;
      return socket;
    },
    ...dependencyOverrides
  };
  const session = new TunnelSession(pair[1], credential, { ...options, ...overrides }, dependencies);
  session.start(initialData);
  const response = new Response(null, { status: 101, webSocket: pair[0] });
  const client = response.webSocket!;
  client.binaryType = "arraybuffer";
  client.accept({ allowHalfOpen: true });
  return {
    client,
    get connectCalls() {
      return connectCalls;
    }
  };
}

describe("full-duplex tunnel session", () => {
  it("uses a functioning in-runtime WebSocketPair harness", async () => {
    const pair = new WebSocketPair();
    pair[1].accept();
    const response = new Response(null, { status: 101, webSocket: pair[0] });
    const client = response.webSocket!;
    client.binaryType = "arraybuffer";
    client.accept();
    const received = new Promise<unknown>((resolve) =>
      pair[1].addEventListener("message", (event) => resolve(event.data), { once: true })
    );
    client.send(Uint8Array.of(1, 2, 3));
    expect(await binaryData(await received)).toEqual(Uint8Array.of(1, 2, 3));
    client.close(1000, "done");
  });

  it("parses a handshake split across several WebSocket messages and preserves payload", async () => {
    const socket = new MemorySocket();
    const harness = createSession(socket, { protocolMode: "vl", TR_PASSWORD: "unit-test-tr-password" });
    const response = nextMessage(harness.client);
    const bytes = validSessionRequest(Uint8Array.of(9, 8, 7));
    harness.client.send(bytes.subarray(0, 3));
    harness.client.send(bytes.subarray(3, 19));
    harness.client.send(bytes.subarray(19));
    expect(await response).toEqual(Uint8Array.of(0, 0));
    await waitFor(() => socket.writes.length === 1);
    expect(socket.writes).toEqual([Uint8Array.of(9, 8, 7)]);
    expect(harness.connectCalls).toBe(1);
    harness.client.close(1000, "done");
  });

  it("keeps HTTP early data on the Vl parser when Tr is enabled", async () => {
    const password = "unit-test-tr-password";
    const socket = new MemorySocket();
    const earlyData = trRequest(password);
    const harness = createSession(socket, { protocolMode: "vl", TR_PASSWORD: password }, {}, earlyData);
    const closeEvent = await nextClose(harness.client);

    expect(closeEvent.code).toBe(1002);
    expect(closeEvent.reason).toBe("invalid request");
    expect(harness.connectCalls).toBe(0);
  });

  it("accepts a fragmented Tr handshake without sending a Vl response header", async () => {
    const password = "unit-test-tr-password";
    const payload = Uint8Array.of(0x16, 0x03, 0x01, 0x00, 0x09, 0x01, 0x02, 0x03);
    const request = trRequest(password, { host: "example.com", payload });
    const socket = new MemorySocket();
    const harness = createSession(socket, { protocolMode: "tr", TR_PASSWORD: password });
    const destinationResponse = nextMessage(harness.client);

    harness.client.send(request.subarray(0, 13));
    harness.client.send(request.subarray(13, 57));
    harness.client.send(request.subarray(57, 64));
    harness.client.send(request.subarray(64));

    await waitFor(() => socket.writes.length === 1);
    expect(socket.writes).toEqual([payload]);
    expect(harness.connectCalls).toBe(1);
    await waitFor(() => socket.readable.locked);

    const serverBytes = Uint8Array.of(0x16, 0x03, 0x03, 0x00, 0x04);
    socket.push(serverBytes);
    expect(await destinationResponse).toEqual(serverBytes);

    harness.client.close(1000, "done");
  });

  it("rejects a Tr password mismatch before opening TCP", async () => {
    const socket = new MemorySocket();
    const harness = createSession(socket, { protocolMode: "tr", TR_PASSWORD: "unit-test-tr-password" });
    const closed = nextClose(harness.client);
    harness.client.send(trRequest("incorrect-password"));

    const closeEvent = await closed;
    expect(closeEvent.code).toBe(1008);
    expect(closeEvent.reason).toBe("authentication failed");
    expect(harness.connectCalls).toBe(0);
  });

  it("rejects an invalid UUID before opening TCP", async () => {
    const socket = new MemorySocket();
    const harness = createSession(socket);
    const closed = nextClose(harness.client);
    const invalid = VALID_UUID_BYTES.slice();
    invalid[0] = 1;
    harness.client.send(requestBytes({ uuid: invalid }));
    const closeEvent = await closed;
    expect(closeEvent.code).toBe(1008);
    expect(closeEvent.reason).toBe("authentication failed");
    expect(harness.connectCalls).toBe(0);
  });

  it("rejects malformed binary handshakes without opening TCP", async () => {
    const socket = new MemorySocket();
    const harness = createSession(socket);
    const closed = nextClose(harness.client);
    harness.client.send(Uint8Array.of(9));
    const closeEvent = await closed;
    expect(closeEvent.code).toBe(1002);
    expect(closeEvent.reason).toBe("invalid request");
    expect(harness.connectCalls).toBe(0);
  });

  it("rejects UDP commands before resolving or connecting a destination", async () => {
    let dnsCalls = 0;
    const socket = new MemorySocket();
    const harness = createSession(
      socket,
      {},
      {
        resolveDNS: async () => {
          dnsCalls += 1;
          return ["93.184.216.34"];
        }
      }
    );
    const closed = nextClose(harness.client);
    harness.client.send(requestBytes({ command: 2 }));
    const closeEvent = await closed;
    expect(closeEvent.code).toBe(1008);
    expect(closeEvent.reason).toBe("TCP command required");
    expect(dnsCalls).toBe(0);
    expect(harness.connectCalls).toBe(0);
  });

  it("reports destination-policy rejection to the client", async () => {
    const socket = new MemorySocket();
    const harness = createSession(socket);
    const closed = nextClose(harness.client);
    harness.client.send(requestBytes({ addressType: 1, address: Uint8Array.of(127, 0, 0, 1) }));
    const closeEvent = await closed;
    expect(closeEvent.code).toBe(1008);
    expect(closeEvent.reason).toBe("private or reserved destination blocked");
    expect(harness.connectCalls).toBe(0);
  });

  it("reports Cloudflare-owned ranges distinctly", async () => {
    const socket = new MemorySocket();
    const harness = createSession(socket);
    const closed = nextClose(harness.client);
    harness.client.send(requestBytes({ addressType: 1, address: Uint8Array.of(104, 16, 0, 1) }));
    const closeEvent = await closed;
    expect(closeEvent.code).toBe(1008);
    expect(closeEvent.reason).toBe("Cloudflare-owned destination blocked");
    expect(harness.connectCalls).toBe(0);
  });

  it("reports the platform-blocked destination port", async () => {
    const socket = new MemorySocket();
    const harness = createSession(socket);
    const closed = nextClose(harness.client);
    harness.client.send(requestBytes({ port: 25 }));
    const closeEvent = await closed;
    expect(closeEvent.code).toBe(1008);
    expect(closeEvent.reason).toBe("destination port 25 is unavailable");
    expect(harness.connectCalls).toBe(0);
  });

  it("reports attempts to connect to the Worker itself", async () => {
    const socket = new MemorySocket();
    const harness = createSession(socket);
    const closed = nextClose(harness.client);
    const hostname = new TextEncoder().encode("edge.example.com");
    harness.client.send(requestBytes({ addressType: 2, address: Uint8Array.from([hostname.byteLength, ...hostname]) }));
    const closeEvent = await closed;
    expect(closeEvent.code).toBe(1008);
    expect(closeEvent.reason).toBe("destination is this Worker");
    expect(harness.connectCalls).toBe(0);
  });

  it("reports DNS failure without exposing resolver details", async () => {
    const socket = new MemorySocket();
    const harness = createSession(
      socket,
      {},
      {
        resolveDNS: async () => {
          throw new Error("private resolver implementation detail");
        }
      }
    );
    const closed = nextClose(harness.client);
    harness.client.send(validSessionRequest());
    const closeEvent = await closed;
    expect(closeEvent.code).toBe(1008);
    expect(closeEvent.reason).toBe("DNS lookup failed");
    expect(closeEvent.reason).not.toContain("private resolver");
  });

  it("reports TCP connect failure to the client", async () => {
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
    const closed = nextClose(harness.client);
    harness.client.send(validSessionRequest());
    const closeEvent = await closed;
    expect(closeEvent.code).toBe(1011);
    expect(closeEvent.reason).toBe("TCP connection failed");
    expect(closeEvent.reason).not.toContain("private network");
  });

  it("closes unauthenticated sessions at the handshake deadline", async () => {
    const socket = new MemorySocket();
    const harness = createSession(socket, { handshakeTimeoutMs: 20 });
    const closeEvent = await nextClose(harness.client);
    expect(closeEvent.code).toBe(1008);
    expect(closeEvent.reason).toContain("handshake timed out");
    expect(harness.connectCalls).toBe(0);
  });

  it("aborts pending DNS resolution when the client closes", async () => {
    const socket = new MemorySocket();
    let resolverSignal: AbortSignal | undefined;
    const harness = createSession(
      socket,
      { connectTimeoutMs: 1_000 },
      {
        resolveDNS: async (_hostname, signal) => {
          resolverSignal = signal;
          return new Promise<readonly string[]>((_resolve, reject) => {
            signal?.addEventListener("abort", () => reject(new DOMException("DNS resolution aborted", "AbortError")), {
              once: true
            });
          });
        }
      }
    );

    harness.client.send(validSessionRequest());
    await waitFor(() => resolverSignal !== undefined);
    harness.client.close(1000, "done");

    await waitFor(() => resolverSignal?.aborted === true);
    expect(harness.connectCalls).toBe(0);
  });

  it("bounds DNS resolution by the connect timeout even if a resolver ignores cancellation", async () => {
    const socket = new MemorySocket();
    let resolverSignal: AbortSignal | undefined;
    const harness = createSession(
      socket,
      { connectTimeoutMs: 20 },
      {
        resolveDNS: async (_hostname, signal) => {
          resolverSignal = signal;
          return new Promise<readonly string[]>(() => undefined);
        }
      }
    );
    const closed = nextClose(harness.client);

    harness.client.send(validSessionRequest());
    expect((await closed).code).toBe(1011);

    expect(resolverSignal?.aborted).toBe(true);
    expect(harness.connectCalls).toBe(0);
  });

  it("aborts a pending TCP open when the client closes", async () => {
    const socket = new MemorySocket();
    let connectSignal: AbortSignal | undefined;
    let connectStarted = false;
    const harness = createSession(
      socket,
      { connectTimeoutMs: 1_000 },
      {
        connect: async (_destination, _timeoutMilliseconds, signal) => {
          connectStarted = true;
          connectSignal = signal;
          return new Promise<Socket>((_resolve, reject) => {
            signal?.addEventListener("abort", () => reject(new DOMException("TCP connection aborted", "AbortError")), {
              once: true
            });
          });
        }
      }
    );

    harness.client.send(validSessionRequest());
    await waitFor(() => connectStarted && connectSignal !== undefined);
    harness.client.close(1000, "done");

    await waitFor(() => connectSignal?.aborted === true);
    expect(socket.closeCalls).toBe(0);
  });

  it("forwards destination bytes after the one-time response header", async () => {
    const socket = new MemorySocket();
    const harness = createSession(socket);
    const header = nextMessage(harness.client);
    harness.client.send(validSessionRequest());
    expect(await header).toEqual(Uint8Array.of(0, 0));
    const payload = nextMessage(harness.client);
    socket.push(Uint8Array.of(1, 2, 3, 4));
    expect(await payload).toEqual(Uint8Array.of(1, 2, 3, 4));
    harness.client.close(1000, "done");
  });

  it("chunks large destination reads into bounded, ordered WebSocket messages", async () => {
    const socket = new MemorySocket();
    const harness = createSession(socket);
    const header = nextMessage(harness.client);
    harness.client.send(validSessionRequest());
    expect(await header).toEqual(Uint8Array.of(0, 0));

    const payload = Uint8Array.from({ length: 2 * 64 * 1024 + 17 }, (_, index) => index % 251);
    const messages = nextMessages(harness.client, 3);
    socket.push(payload);

    const chunks = await messages;
    expect(chunks.map((chunk) => chunk.byteLength)).toEqual([64 * 1024, 64 * 1024, 17]);
    expect(chunks[0]).toEqual(payload.subarray(0, 64 * 1024));
    expect(chunks[1]).toEqual(payload.subarray(64 * 1024, 2 * 64 * 1024));
    expect(chunks[2]).toEqual(payload.subarray(2 * 64 * 1024));
    harness.client.close(1000, "done");
  });

  it("closes idle authenticated sessions and releases TCP stream locks", async () => {
    const socket = new MemorySocket();
    const harness = createSession(socket, { idleTimeoutMs: 30 });
    const header = nextMessage(harness.client);
    const closed = nextClose(harness.client);
    harness.client.send(validSessionRequest());
    expect(await header).toEqual(Uint8Array.of(0, 0));

    const closeEvent = await closed;
    expect(closeEvent.code).toBe(1000);
    expect(closeEvent.reason).toBe("connection idle timeout");
    await waitFor(() => socket.closeCalls > 0 && !socket.readable.locked && !socket.writable.locked);
  });

  it("reciprocates client close and closes the TCP socket exactly once", async () => {
    const socket = new MemorySocket();
    const harness = createSession(socket);
    const header = nextMessage(harness.client);
    harness.client.send(validSessionRequest());
    await header;
    const reciprocalClose = nextClose(harness.client);
    harness.client.close(1000, "done");
    const closeEvent = await reciprocalClose;
    expect(closeEvent.code).toBe(1000);
    expect(closeEvent.reason).toBe("done");
    await waitFor(() => socket.closeCalls > 0 && !socket.readable.locked && !socket.writable.locked);
    expect(socket.closeCalls).toBe(1);
  });

  it("keeps the TCP writable half open after destination EOF until the client closes", async () => {
    const socket = new MemorySocket();
    const harness = createSession(socket, { idleTimeoutMs: 2_000 });
    const header = nextMessage(harness.client);
    harness.client.send(validSessionRequest());
    expect(await header).toEqual(Uint8Array.of(0, 0));

    socket.end();
    await waitFor(() => !socket.readable.locked);
    expect(socket.closeCalls).toBe(0);
    expect(harness.client.readyState).toBe(WebSocket.OPEN);

    harness.client.send(Uint8Array.of(4, 5, 6));
    await waitFor(() => socket.writes.length === 1);
    expect(socket.writes).toEqual([Uint8Array.of(4, 5, 6)]);

    const reciprocalClose = nextClose(harness.client);
    harness.client.close(1000, "done");
    expect((await reciprocalClose).code).toBe(1000);
    await waitFor(() => socket.closeCalls > 0 && !socket.readable.locked && !socket.writable.locked);
    expect(socket.closeCalls).toBe(1);
  });

  it("serializes client writes and preserves ordering under backpressure", async () => {
    const socket = new MemorySocket(5);
    const harness = createSession(socket);
    const header = nextMessage(harness.client);
    harness.client.send(validSessionRequest());
    await header;
    harness.client.send(Uint8Array.of(1));
    harness.client.send(Uint8Array.of(2));
    harness.client.send(Uint8Array.of(3));
    await waitFor(() => socket.writes.length === 3);
    expect(socket.writes).toEqual([Uint8Array.of(1), Uint8Array.of(2), Uint8Array.of(3)]);
    expect(socket.maximumConcurrentWrites).toBe(1);
    harness.client.close(1000, "done");
  });

  it("enforces the bounded inbound write queue", async () => {
    const socket = new MemorySocket();
    const harness = createSession(socket, { handshakeTimeoutMs: 2_000 });
    const closed = nextClose(harness.client);
    harness.client.send(new Uint8Array(1024 * 1024 + 1));
    expect((await closed).code).toBe(1009);
    expect(harness.connectCalls).toBe(0);
  });
});
