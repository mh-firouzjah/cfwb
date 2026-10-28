import { describe, expect, it } from "vitest";
import { waitForSocketOpen } from "../src/tcp";

function pendingSocket(): { socket: Socket; closeCalls: () => number } {
  let closes = 0;
  let socket: Socket;
  socket = {
    opened: new Promise<SocketInfo>(() => undefined),
    closed: new Promise<void>(() => undefined),
    readable: new ReadableStream<Uint8Array>(),
    writable: new WritableStream<Uint8Array>(),
    upgraded: false,
    secureTransport: "off" as const,
    close: async () => {
      closes += 1;
    },
    startTls: () => socket
  };
  return { socket, closeCalls: () => closes };
}

describe("outbound TCP connection deadline", () => {
  it("closes a socket that does not open before the timeout", async () => {
    const pending = pendingSocket();
    await expect(waitForSocketOpen(pending.socket, 10)).rejects.toThrow("connection timed out");
    expect(pending.closeCalls()).toBe(1);
  });

  it("returns an opened socket and cancels the deadline", async () => {
    const pending = pendingSocket();
    const opened = Object.defineProperty(pending.socket, "opened", {
      value: Promise.resolve({ remoteAddress: "93.184.216.34:443" } satisfies SocketInfo)
    });
    await expect(waitForSocketOpen(opened, 100)).resolves.toBe(opened);
    expect(pending.closeCalls()).toBe(0);
  });

  it("closes a pending socket immediately when its session is canceled", async () => {
    const pending = pendingSocket();
    const controller = new AbortController();
    const opening = waitForSocketOpen(pending.socket, 1_000, controller.signal);

    controller.abort();

    await expect(opening).rejects.toThrow("connection canceled");
    expect(pending.closeCalls()).toBe(1);
  });

  it("fails closed for an invalid timeout", async () => {
    const pending = pendingSocket();
    await expect(waitForSocketOpen(pending.socket, 0)).rejects.toThrow("connection timeout is invalid");
    expect(pending.closeCalls()).toBe(1);
  });
});
