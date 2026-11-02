import { describe, expect, it } from "vitest";
import { upgradeWebSocket, WebSocketTransport } from "../src/transport/websocket";

function createHarness() {
  const pair = new WebSocketPair();
  const response = new Response(null, { status: 101, webSocket: pair[0] });
  const client = response.webSocket!;
  client.binaryType = "arraybuffer";
  client.accept({ allowHalfOpen: true });
  const transport = new WebSocketTransport(pair[1]);
  return { client, transport };
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function nextClose(socket: WebSocket): Promise<CloseEvent> {
  return new Promise((resolve) => socket.addEventListener("close", resolve, { once: true }));
}

function nextMessages(socket: WebSocket, count: number): Promise<Uint8Array[]> {
  return new Promise((resolve, reject) => {
    const messages: Uint8Array[] = [];
    const cleanup = () => {
      socket.removeEventListener("message", onMessage);
      socket.removeEventListener("close", onClose);
    };
    const onClose = (event: CloseEvent) => {
      cleanup();
      reject(new Error(`WebSocket closed after ${messages.length} of ${count} messages: ${event.code}`));
    };
    const onMessage = (event: MessageEvent) => {
      if (!(event.data instanceof ArrayBuffer)) {
        cleanup();
        reject(new Error("expected an ArrayBuffer WebSocket message"));
        return;
      }
      messages.push(new Uint8Array(event.data));
      if (messages.length === count) {
        cleanup();
        resolve(messages);
      }
    };
    socket.addEventListener("message", onMessage);
    socket.addEventListener("close", onClose, { once: true });
  });
}

describe("WebSocket byte-stream adapter", () => {
  it("preserves binary frame order as stream chunks", async () => {
    const { client, transport } = createHarness();
    const reader = transport.readable.getReader();
    client.send(Uint8Array.of(1, 2));
    client.send(Uint8Array.of(3, 4));

    expect(await reader.read()).toEqual({ done: false, value: Uint8Array.of(1, 2) });
    expect(await reader.read()).toEqual({ done: false, value: Uint8Array.of(3, 4) });

    const closed = nextClose(client);
    client.close(1000, "test complete");
    expect((await closed).code).toBe(1000);
    expect((await reader.read()).done).toBe(true);
  });

  it("rejects text frames at the transport boundary", async () => {
    const { client, transport } = createHarness();
    const reader = transport.readable.getReader();
    const closed = nextClose(client);
    const read = reader.read();
    client.send("not binary");

    await expect(read).rejects.toThrow("binary frames required");
    const closeEvent = await closed;
    expect(closeEvent.code).toBe(1003);
    expect(closeEvent.reason).toBe("binary frames required");
  });

  it("accepts an inbound message larger than the former 1 MiB limit", async () => {
    const { client, transport } = createHarness();
    const reader = transport.readable.getReader();
    const payload = new Uint8Array(1024 * 1024 + 1);
    payload[0] = 0x12;
    payload[payload.length - 1] = 0x34;

    client.send(payload);

    const result = await reader.read();
    expect(result.done).toBe(false);
    expect(result.value?.byteLength).toBe(payload.byteLength);
    expect(result.value?.[0]).toBe(0x12);
    expect(result.value?.[payload.length - 1]).toBe(0x34);

    const closed = nextClose(client);
    client.close(1000, "test complete");
    expect((await closed).code).toBe(1000);
    expect((await reader.read()).done).toBe(true);
  });

  it("sends each outbound stream write as one WebSocket message", async () => {
    const { client, transport } = createHarness();
    const writer = transport.writable.getWriter();
    const payload = Uint8Array.from({ length: 2 * 64 * 1024 + 17 }, (_, index) => index % 251);
    const messages = nextMessages(client, 1);

    await writer.write(payload);
    const chunks = await messages;

    expect(chunks).toHaveLength(1);
    expect(chunks[0]).toEqual(payload);

    transport.close("normal");
    writer.releaseLock();
  });

  it("maps transport-neutral tunnel termination to WebSocket close information", async () => {
    const { client, transport } = createHarness();
    const closed = nextClose(client);
    transport.close("authentication_failed");

    const closeEvent = await closed;
    expect(closeEvent.code).toBe(1008);
    expect(closeEvent.reason).toBe("authentication failed");
    await expect(transport.closed).resolves.toBeUndefined();
  });

  it.each([
    ["tcp_failed", 1011, "TCP connection failed"],
    ["handshake_timeout", 1008, "handshake timed out"],
    ["transport_failed", 1011, "WebSocket transport failed"]
  ] as const)("maps %s to the expected WebSocket close", async (reason, code, message) => {
    const { client, transport } = createHarness();
    const closed = nextClose(client);
    transport.close(reason);

    const closeEvent = await closed;
    expect(closeEvent.code).toBe(code);
    expect(closeEvent.reason).toBe(message);
  });

  it("echoes a safe peer close code and reason", async () => {
    const { client, transport } = createHarness();
    const closed = nextClose(client);
    client.close(3001, "client complete");

    const closeEvent = await closed;
    expect(closeEvent.code).toBe(3001);
    expect(closeEvent.reason).toBe("client complete");
    await expect(transport.closed).resolves.toBeUndefined();
  });

  it("decodes WebSocket early data before exposing the byte stream", async () => {
    let earlyDataReadable: ReadableStream<Uint8Array> | undefined;
    const response = upgradeWebSocket(
      new Request("https://worker.example/secret", {
        headers: { Upgrade: "websocket", "Sec-WebSocket-Protocol": "AA" }
      }),
      (value) => {
        earlyDataReadable = value.readable;
      }
    );

    expect(response?.status).toBe(101);
    expect(response?.headers.get("Sec-WebSocket-Protocol")).toBe("AA");
    if (earlyDataReadable === undefined) throw new Error("WebSocket upgrade did not provide a readable stream");
    const reader = earlyDataReadable.getReader();
    expect(await reader.read()).toEqual({ done: false, value: Uint8Array.of(0) });
    response?.webSocket?.accept();
    response?.webSocket?.close(1000, "test complete");
  });

  it("imposes no size cap of its own on early data", async () => {
    const large = new Uint8Array(8_192).fill(7);
    let earlyDataReadable: ReadableStream<Uint8Array> | undefined;
    const response = upgradeWebSocket(
      new Request("https://worker.example/secret", {
        headers: { Upgrade: "websocket", "Sec-WebSocket-Protocol": encodeBase64Url(large) }
      }),
      (transport) => {
        earlyDataReadable = transport.readable;
      }
    );
    expect(response?.status).toBe(101);
    if (earlyDataReadable === undefined) throw new Error("WebSocket upgrade did not provide a readable stream");
    expect(await earlyDataReadable.getReader().read()).toEqual({ done: false, value: large });
    response?.webSocket?.accept();
    response?.webSocket?.close(1000, "test complete");
  });

  it("rejects malformed early-data headers before upgrading", () => {
    const malformed = upgradeWebSocket(
      new Request("https://worker.example/secret", {
        headers: { Upgrade: "websocket", "Sec-WebSocket-Protocol": "not base64url!" }
      }),
      () => {
        throw new Error("session must not be created");
      }
    );
    expect(malformed).toBeUndefined();
  });

  it("closes the WebSocket after the upstream byte stream reaches EOF", async () => {
    const { client, transport } = createHarness();
    const payload = Uint8Array.of(4, 5, 6);
    const messages = nextMessages(client, 1);
    const closed = nextClose(client);
    const upstream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(payload);
        controller.close();
      }
    });

    await upstream.pipeTo(transport.writable);

    expect(await messages).toEqual([payload]);
    const closeEvent = await closed;
    expect(closeEvent.code).toBe(1000);
    expect(closeEvent.reason).toBe("normal closure");
    await expect(transport.closed).resolves.toBeUndefined();
  });

  it("closes the WebSocket when the readable byte stream is canceled", async () => {
    const { client, transport } = createHarness();
    const closed = nextClose(client);

    await transport.readable.cancel();

    const closeEvent = await closed;
    expect(closeEvent.code).toBe(1000);
    await expect(transport.closed).resolves.toBeUndefined();
  });

  it("closes the WebSocket when the writable byte stream is aborted", async () => {
    const { client, transport } = createHarness();
    const writer = transport.writable.getWriter();
    const closed = nextClose(client);

    await writer.abort(new Error("test abort"));
    writer.releaseLock();

    const closeEvent = await closed;
    expect(closeEvent.code).toBe(1011);
    expect(closeEvent.reason).toBe("WebSocket transport failed");
    await expect(transport.closed).resolves.toBeUndefined();
  });
});
