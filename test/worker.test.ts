import { createExecutionContext, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker, { createWorker } from "../src/index";
import { requestBytes, VALID_UUID } from "./fixtures";
import type { Destination } from "../src/protocol";
import type { UpstreamConnection } from "../src/transport";
import { trRequest } from "./trojan-fixtures";

const TEST_VL_PATH = "/unit-test-path-0001";
const TEST_TR_PATH = "/unit-test-tr-path-0002";
const TEST_TR_PASSWORD = "unit-test-tr-password";
const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

function request(path: string): InstanceType<typeof IncomingRequest> {
  return new IncomingRequest(`https://worker.example${path}`, {
    headers: { Upgrade: "websocket" }
  });
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function encodeHost(host: string): Uint8Array {
  const bytes = new TextEncoder().encode(host);
  return Uint8Array.from([bytes.byteLength, ...bytes]);
}

type WorkerHandler = ReturnType<typeof createWorker>;
type WorkerEnvironment = Parameters<NonNullable<WorkerHandler["fetch"]>>[1];

async function callWorkerFetch(
  handler: WorkerHandler,
  workerRequest: ReturnType<typeof request>,
  env: WorkerEnvironment
): Promise<Response> {
  const fetchHandler = handler.fetch;
  if (fetchHandler === undefined) throw new Error("Worker fetch handler is not configured");
  return await fetchHandler(workerRequest, env, createExecutionContext());
}

function expectUpgrade(response: Response): void {
  expect(response.status).toBe(101);
  expect(response.webSocket).not.toBeNull();
  response.webSocket?.accept();
  response.webSocket?.close(1000, "test complete");
}

class MemoryUpstreamConnection implements UpstreamConnection {
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;
  readonly writes: Uint8Array[] = [];
  #controller!: ReadableStreamDefaultController<Uint8Array>;
  #readEnded = false;
  #closeCalls = 0;

  constructor() {
    this.readable = new ReadableStream<Uint8Array>({
      start: (controller) => {
        this.#controller = controller;
      }
    });
    this.writable = new WritableStream<Uint8Array>({
      write: (chunk) => {
        this.writes.push(chunk.slice());
      }
    });
  }

  get closeCalls(): number {
    return this.#closeCalls;
  }

  push(bytes: Uint8Array): void {
    if (!this.#readEnded) this.#controller.enqueue(bytes.slice());
  }

  async close(): Promise<void> {
    this.#closeCalls += 1;
    if (this.#readEnded) return;
    this.#readEnded = true;
    try {
      this.#controller.close();
    } catch {
      // The session may already have canceled or closed the readable side.
    }
  }
}

function nextBinaryMessage(socket: WebSocket): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      socket.removeEventListener("message", onMessage);
      socket.removeEventListener("close", onClose);
    };
    const onClose = (event: CloseEvent) => {
      cleanup();
      reject(new Error(`WebSocket closed before binary message: ${event.code}`));
    };
    const onMessage = (event: MessageEvent) => {
      cleanup();
      if (event.data instanceof ArrayBuffer) {
        resolve(new Uint8Array(event.data));
        return;
      }
      if (ArrayBuffer.isView(event.data)) {
        resolve(
          new Uint8Array(event.data.buffer.slice(event.data.byteOffset, event.data.byteOffset + event.data.byteLength))
        );
        return;
      }
      reject(new Error("expected a binary WebSocket message"));
    };
    socket.addEventListener("message", onMessage, { once: true });
    socket.addEventListener("close", onClose, { once: true });
  });
}

async function waitFor(predicate: () => boolean, timeoutMs = 1_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("condition timed out");
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
}

async function openTestClient(handler: ReturnType<typeof createWorker>, path: string): Promise<WebSocket> {
  const response = await callWorkerFetch(handler, request(path), {
    UUID: VALID_UUID,
    VL_PATH: TEST_VL_PATH,
    TR_PASSWORD: TEST_TR_PASSWORD,
    TR_PATH: TEST_TR_PATH
  });
  expect(response.status).toBe(101);
  const socket = response.webSocket;
  if (socket === null || socket === undefined) throw new Error("Worker upgrade did not return a WebSocket");
  socket.binaryType = "arraybuffer";
  socket.accept({ allowHalfOpen: true });
  return socket;
}

describe("Worker HTTP and WebSocket boundary", () => {
  it("serves an innocuous HTTP response without proxy disclosure", async () => {
    const response = await SELF.fetch("https://edge.example.com/");
    expect(response.status).toBe(404);
    expect(await response.text()).toBe("Not Found\n");
  });

  it("rejects non-WebSocket requests to the endpoint", async () => {
    const response = await SELF.fetch(`https://edge.example.com${TEST_VL_PATH}`);
    expect(response.status).toBe(404);
  });

  it("rejects non-GET WebSocket upgrade requests", async () => {
    const response = await callWorkerFetch(
      worker,
      new Request(`https://worker.example${TEST_VL_PATH}`, {
        method: "POST",
        headers: { Upgrade: "websocket" }
      }),
      {
        UUID: VALID_UUID,
        VL_PATH: TEST_VL_PATH,
        TR_PASSWORD: TEST_TR_PASSWORD,
        TR_PATH: TEST_TR_PATH
      }
    );
    expect(response.status).toBe(404);
    expect(await response.text()).toBe("Not Found\n");
  });

  it("rejects an invalid path without identifying the endpoint", async () => {
    const response = await SELF.fetch("https://edge.example.com/wrong", {
      headers: { Upgrade: "websocket" }
    });
    expect(response.status).toBe(404);
  });

  it("rejects plaintext HTTP WebSocket upgrades with the generic response", async () => {
    const response = await SELF.fetch(`http://edge.example.com${TEST_VL_PATH}`, { headers: { Upgrade: "websocket" } });
    expect(response.status).toBe(404);
    expect(await response.text()).toBe("Not Found\n");
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it("upgrades a configured WebSocket path through the Worker runtime", async () => {
    const response = await SELF.fetch(`https://worker.example${TEST_VL_PATH}`, {
      headers: { Upgrade: "websocket" }
    });
    expectUpgrade(response);
  });

  it("accepts configured path secrets at both length boundaries", async () => {
    for (const length of [16, 128]) {
      const path = `/${"a".repeat(length)}`;
      const response = await callWorkerFetch(worker, request(path), {
        UUID: VALID_UUID,
        VL_PATH: path,
        TR_PASSWORD: TEST_TR_PASSWORD,
        TR_PATH: TEST_TR_PATH
      });
      expectUpgrade(response);
    }
  });

  it.each(["/short", `/${"a".repeat(129)}`, "/path/with/slashes-123456", "/bad.path-123456789"])(
    "fails closed with a configuration error for invalid VL_PATH %s",
    async (path) => {
      const response = await callWorkerFetch(worker, request(path), {
        UUID: VALID_UUID,
        VL_PATH: path,
        TR_PASSWORD: TEST_TR_PASSWORD,
        TR_PATH: TEST_TR_PATH
      });
      expect(response.status).toBe(500);
      expect(await response.text()).toBe("Misconfigured\n");
    }
  );

  it.each([
    ["missing UUID", { UUID: "" }],
    ["invalid UUID", { UUID: "not-a-uuid" }],
    ["missing VL_PATH", { VL_PATH: "" }],
    ["missing TR_PASSWORD", { TR_PASSWORD: "" }],
    ["oversized TR_PASSWORD", { TR_PASSWORD: "x".repeat(513) }],
    ["missing TR_PATH", { TR_PATH: "" }],
    ["invalid TR_PATH", { TR_PATH: "invalid-trojan-path" }],
    ["identical VL_PATH and TR_PATH", { TR_PATH: TEST_VL_PATH }]
  ])("requires both protocols to be configured: %s", async (_description, override) => {
    for (const path of [TEST_VL_PATH, TEST_TR_PATH]) {
      const response = await callWorkerFetch(worker, request(path), {
        UUID: VALID_UUID,
        VL_PATH: TEST_VL_PATH,
        TR_PASSWORD: TEST_TR_PASSWORD,
        TR_PATH: TEST_TR_PATH,
        ...override
      });
      expect(response.status).toBe(500);
      expect(await response.text()).toBe("Misconfigured\n");
    }
  });

  it.each([
    {
      name: "VLESS",
      path: TEST_VL_PATH,
      wire: requestBytes({
        address: Uint8Array.from([11, ...new TextEncoder().encode("example.com")]),
        payload: Uint8Array.of(1, 2, 3)
      }),
      initialPayload: Uint8Array.of(1, 2, 3),
      responseHeader: Uint8Array.of(0, 0)
    },
    {
      name: "Trojan",
      path: TEST_TR_PATH,
      wire: trRequest(TEST_TR_PASSWORD, { host: "example.com", payload: Uint8Array.of(1, 2, 3) }),
      initialPayload: Uint8Array.of(1, 2, 3),
      responseHeader: undefined
    }
  ])("relays a valid $name handshake through Worker, protocol adapter, Session and WebSocket", async (testCase) => {
    const upstream = new MemoryUpstreamConnection();
    const connectedDestinations: Destination[] = [];
    const handler = createWorker({
      connect: async (destination) => {
        connectedDestinations.push(destination);
        return upstream;
      }
    });

    const client = await openTestClient(handler, testCase.path);
    const response = testCase.responseHeader === undefined ? undefined : nextBinaryMessage(client);
    client.send(testCase.wire);

    if (response !== undefined) {
      await expect(response).resolves.toEqual(testCase.responseHeader);
    }
    await waitFor(() => upstream.writes.length === 1);
    expect(upstream.writes[0]).toEqual(testCase.initialPayload);
    expect(connectedDestinations).toEqual([{ host: "example.com", port: 443 }]);

    client.send(Uint8Array.of(4, 5, 6));
    await waitFor(() => upstream.writes.length === 2);
    expect(upstream.writes[1]).toEqual(Uint8Array.of(4, 5, 6));

    const downstream = nextBinaryMessage(client);
    upstream.push(Uint8Array.of(7, 8, 9));
    await expect(downstream).resolves.toEqual(Uint8Array.of(7, 8, 9));

    const closed = new Promise<CloseEvent>((resolve) => client.addEventListener("close", resolve, { once: true }));
    client.close(1000, "integration test complete");
    await closed;
    await waitFor(() => upstream.closeCalls === 1);
    expect(upstream.closeCalls).toBe(1);
  });

  it("closes only the WebSocket whose destination connection failed", async () => {
    const upstream = new MemoryUpstreamConnection();
    const handler = createWorker({
      connect: async (destination) => {
        if (destination.host === "fail.example") throw new Error("temporary connection failure");
        return upstream;
      }
    });

    const failedClient = await openTestClient(handler, TEST_VL_PATH);
    const workingClient = await openTestClient(handler, TEST_VL_PATH);
    const failedClosed = new Promise<CloseEvent>((resolve) =>
      failedClient.addEventListener("close", resolve, { once: true })
    );
    const response = nextBinaryMessage(workingClient);

    failedClient.send(requestBytes({ address: encodeHost("fail.example") }));
    workingClient.send(requestBytes({ address: encodeHost("good.example") }));

    const failedClose = await failedClosed;
    expect(failedClose.code).toBe(1011);
    await expect(response).resolves.toEqual(Uint8Array.of(0, 0));
    expect(workingClient.readyState).toBe(WebSocket.OPEN);

    workingClient.send(Uint8Array.of(1, 2, 3));
    await waitFor(() => upstream.writes.length === 1);
    expect(upstream.writes[0]).toEqual(Uint8Array.of(1, 2, 3));

    const workingClosed = new Promise<CloseEvent>((resolve) =>
      workingClient.addEventListener("close", resolve, { once: true })
    );
    workingClient.close(1000, "test complete");
    await workingClosed;
  });

  it("keeps the VLESS and Trojan paths protocol-isolated", async () => {
    const cases = [
      { path: TEST_VL_PATH, bytes: trRequest(TEST_TR_PASSWORD) },
      { path: TEST_TR_PATH, bytes: requestBytes() }
    ];

    for (const testCase of cases) {
      const response = await SELF.fetch(`https://worker.example${testCase.path}`, {
        headers: { Upgrade: "websocket" }
      });
      expect(response.status).toBe(101);
      const socket = response.webSocket!;
      socket.accept();
      const closed = new Promise<CloseEvent>((resolve) => socket.addEventListener("close", resolve, { once: true }));
      socket.send(testCase.bytes);
      const closeEvent = await closed;
      expect(closeEvent.code).toBe(1002);
      expect(closeEvent.reason).toBe("invalid request");
    }
  });

  it("parses a complete Trojan handshake supplied as WebSocket early data", async () => {
    const payload = Uint8Array.of(4, 5, 6);
    const earlyData = encodeBase64Url(trRequest(TEST_TR_PASSWORD, { host: "early.example", payload }));
    const upstream = new MemoryUpstreamConnection();
    const destinations: Destination[] = [];
    const handler = createWorker({
      connect: async (destination) => {
        destinations.push(destination);
        return upstream;
      }
    });
    const response = await callWorkerFetch(
      handler,
      new IncomingRequest(`https://worker.example${TEST_TR_PATH}`, {
        headers: { Upgrade: "websocket", "Sec-WebSocket-Protocol": earlyData }
      }),
      {
        UUID: VALID_UUID,
        VL_PATH: TEST_VL_PATH,
        TR_PASSWORD: TEST_TR_PASSWORD,
        TR_PATH: TEST_TR_PATH
      }
    );

    expect(response.status).toBe(101);
    expect(response.headers.get("Sec-WebSocket-Protocol")).toBe(earlyData);
    const client = response.webSocket;
    if (client === null || client === undefined) throw new Error("WebSocket upgrade did not return a client socket");
    client.accept();
    await waitFor(() => upstream.writes.length === 1);
    expect(upstream.writes[0]).toEqual(payload);
    expect(destinations).toEqual([{ host: "early.example", port: 443 }]);

    const closed = new Promise<CloseEvent>((resolve) => client.addEventListener("close", resolve, { once: true }));
    client.close(1000, "test complete");
    await closed;
    await waitFor(() => upstream.closeCalls === 1);
  });

  it("parses a complete VL handshake and forwards its payload from WebSocket early data", async () => {
    const payload = Uint8Array.of(1, 2, 3);
    const wire = requestBytes({
      address: encodeHost("early.example"),
      payload
    });
    const earlyData = encodeBase64Url(wire);
    const upstream = new MemoryUpstreamConnection();
    const destinations: Destination[] = [];
    const handler = createWorker({
      connect: async (destination) => {
        destinations.push(destination);
        return upstream;
      }
    });
    const response = await callWorkerFetch(
      handler,
      new IncomingRequest(`https://worker.example${TEST_VL_PATH}`, {
        headers: { Upgrade: "websocket", "Sec-WebSocket-Protocol": earlyData }
      }),
      {
        UUID: VALID_UUID,
        VL_PATH: TEST_VL_PATH,
        TR_PASSWORD: TEST_TR_PASSWORD,
        TR_PATH: TEST_TR_PATH
      }
    );

    expect(response.status).toBe(101);
    expect(response.headers.get("Sec-WebSocket-Protocol")).toBe(earlyData);
    const client = response.webSocket;
    if (client === null || client === undefined) throw new Error("WebSocket upgrade did not return a client socket");
    client.accept();

    await waitFor(() => upstream.writes.length === 1);
    expect(upstream.writes[0]).toEqual(payload);
    expect(destinations).toEqual([{ host: "early.example", port: 443 }]);

    const closed = new Promise<CloseEvent>((resolve) => client.addEventListener("close", resolve, { once: true }));
    client.close(1000, "test complete");
    await closed;
    await waitFor(() => upstream.closeCalls === 1);
  });

  it("rejects malformed WebSocket early data", async () => {
    const response = await SELF.fetch(`https://edge.example.com${TEST_VL_PATH}`, {
      headers: {
        Upgrade: "websocket",
        "Sec-WebSocket-Protocol": "not base64url!"
      }
    });
    expect(response.status).toBe(404);
  });

  it("does not police inbound ports; Cloudflare decides which ports reach the Worker", async () => {
    const response = await SELF.fetch(`https://edge.example.com:8080${TEST_VL_PATH}`, {
      headers: { Upgrade: "websocket" }
    });
    expectUpgrade(response);
  });

  it("closes on text frames", async () => {
    const response = await SELF.fetch(`https://edge.example.com${TEST_VL_PATH}`, {
      headers: { Upgrade: "websocket" }
    });
    const socket = response.webSocket!;
    socket.accept();
    const closed = new Promise<CloseEvent>((resolve) => socket.addEventListener("close", resolve, { once: true }));
    socket.send("not binary");
    const closeEvent = await closed;
    expect(closeEvent.code).toBe(1003);
    expect(closeEvent.reason).toBe("binary frames required");
  });
});
