import { afterEach, describe, expect, it, vi } from "vitest";

const { connectMock } = vi.hoisted(() => ({ connectMock: vi.fn<(...args: unknown[]) => unknown>() }));
vi.mock("cloudflare:sockets", () => ({ connect: connectMock }));

import { connectTCP, readInLargeChunks, waitForSocketOpen } from "../src/transport/tcp";

function mockSocket(opened: Promise<SocketInfo> = Promise.resolve({ remoteAddress: "93.184.216.34:443" })): {
  socket: Socket;
  closeCalls: () => number;
} {
  let closes = 0;
  let socket: Socket;
  socket = {
    opened,
    closed: new Promise<void>(() => undefined),
    readable: new ReadableStream({ type: "bytes" }),
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

afterEach(() => {
  connectMock.mockReset();
  vi.useRealTimers();
});

describe("outbound TCP open", () => {
  it("closes the socket when its open operation rejects", async () => {
    const failure = new Error("socket open failed");
    const pending = mockSocket(Promise.reject(failure));
    await expect(waitForSocketOpen(pending.socket, new AbortController().signal)).rejects.toBe(failure);
    expect(pending.closeCalls()).toBe(1);
  });

  it("resolves for an opened socket without closing it", async () => {
    const pending = mockSocket();
    await expect(waitForSocketOpen(pending.socket, new AbortController().signal)).resolves.toBeUndefined();
    expect(pending.closeCalls()).toBe(0);
  });

  it("closes a pending socket immediately when its session is canceled", async () => {
    vi.useFakeTimers();
    const pending = mockSocket(new Promise<SocketInfo>(() => undefined));
    const controller = new AbortController();
    const opening = waitForSocketOpen(pending.socket, controller.signal);
    controller.abort();
    await expect(opening).rejects.toThrow("connection canceled");
    expect(pending.closeCalls()).toBe(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("honors an AbortSignal that was already aborted", async () => {
    const pending = mockSocket(new Promise<SocketInfo>(() => undefined));
    const controller = new AbortController();
    controller.abort();
    await expect(waitForSocketOpen(pending.socket, controller.signal)).rejects.toThrow("connection canceled");
    expect(pending.closeCalls()).toBe(1);
  });

  it("preserves an explicit cancellation reason", async () => {
    const pending = mockSocket(new Promise<SocketInfo>(() => undefined));
    const controller = new AbortController();
    const reason = new Error("session disposed");
    const opening = waitForSocketOpen(pending.socket, controller.signal);
    controller.abort(reason);
    await expect(opening).rejects.toBe(reason);
  });

  it("preserves the original error when socket cleanup also fails", async () => {
    const pending = mockSocket(new Promise<SocketInfo>(() => undefined));
    pending.socket.close = async () => {
      throw new Error("synthetic close failure");
    };
    const controller = new AbortController();
    const opening = waitForSocketOpen(pending.socket, controller.signal);
    controller.abort();
    await expect(opening).rejects.toThrow("connection canceled");
  });

  it("does not retry a destination rejected by the runtime", async () => {
    const blocked = new Error("proxy request failed, cannot connect to the specified address");
    connectMock.mockReturnValueOnce(mockSocket(Promise.reject(blocked)).socket);
    await expect(connectTCP({ host: "127.0.0.1", port: 443 }, new AbortController().signal)).rejects.toBe(blocked);
    expect(connectMock).toHaveBeenCalledTimes(1);
  });

  it("does not retry a loop or port-25 rejection", async () => {
    for (const message of ["TCP Loop detected", "Connections to port 25 are prohibited"]) {
      connectMock.mockReset();
      const failure = new Error(message);
      connectMock.mockReturnValueOnce(mockSocket(Promise.reject(failure)).socket);
      await expect(connectTCP({ host: "gstatic.com", port: 25 }, new AbortController().signal)).rejects.toBe(failure);
      expect(connectMock).toHaveBeenCalledTimes(1);
    }
  });

  it("retries one non-policy failure and returns the next opened socket", async () => {
    const first = mockSocket(Promise.reject(new Error("temporary network failure")));
    const second = mockSocket();
    connectMock.mockReturnValueOnce(first.socket).mockReturnValueOnce(second.socket);

    const connection = await connectTCP({ host: "gstatic.com", port: 443 }, new AbortController().signal);
    expect(connection.writable).toBe(second.socket.writable);
    expect(first.closeCalls()).toBe(1);
    expect(second.closeCalls()).toBe(0);
    expect(connectMock).toHaveBeenCalledTimes(2);
    await connection.close();
    expect(second.closeCalls()).toBe(1);
  });

  it("does not exceed two attempts for repeated non-policy failures", async () => {
    const first = mockSocket(Promise.reject(new Error("temporary failure one")));
    const secondFailure = new Error("temporary failure two");
    const second = mockSocket(Promise.reject(secondFailure));
    connectMock.mockReturnValueOnce(first.socket).mockReturnValueOnce(second.socket);

    await expect(connectTCP({ host: "gstatic.com", port: 443 }, new AbortController().signal)).rejects.toBe(
      secondFailure
    );
    expect(first.closeCalls()).toBe(1);
    expect(second.closeCalls()).toBe(1);
    expect(connectMock).toHaveBeenCalledTimes(2);
  });

  it("does not retry when the caller aborts the attempt", async () => {
    const pending = mockSocket(new Promise<SocketInfo>(() => undefined));
    connectMock.mockReturnValueOnce(pending.socket);
    const controller = new AbortController();
    const opening = connectTCP({ host: "gstatic.com", port: 443 }, controller.signal);
    controller.abort();
    await expect(opening).rejects.toThrow("connection canceled");
    expect(connectMock).toHaveBeenCalledTimes(1);
    expect(pending.closeCalls()).toBe(1);
  });

  it("rejects a timed-out open without waiting for socket cleanup", async () => {
    vi.useFakeTimers();
    const pending = mockSocket(new Promise<SocketInfo>(() => undefined));
    let closeCalled = false;
    pending.socket.close = () => {
      closeCalled = true;
      return new Promise<void>(() => undefined);
    };

    const opening = waitForSocketOpen(pending.socket, new AbortController().signal, 10);
    const outcome = opening.then(
      () => ({ status: "opened" as const }),
      (error: unknown) => ({ status: "rejected" as const, error })
    );

    await vi.advanceTimersByTimeAsync(10);

    await expect(outcome).resolves.toMatchObject({
      status: "rejected",
      error: expect.objectContaining({ message: "TCP connection timed out" })
    });
    expect(closeCalled).toBe(true);
  });

  it("rejects an already-aborted open without waiting for socket cleanup", async () => {
    const pending = mockSocket(new Promise<SocketInfo>(() => undefined));
    let closeCalled = false;
    pending.socket.close = () => {
      closeCalled = true;
      return new Promise<void>(() => undefined);
    };
    const controller = new AbortController();
    controller.abort();

    await expect(waitForSocketOpen(pending.socket, controller.signal)).rejects.toThrow("connection canceled");
    expect(closeCalled).toBe(true);
  });

  it("times out a pending open and closes its socket", async () => {
    vi.useFakeTimers();
    const pending = mockSocket(new Promise<SocketInfo>(() => undefined));
    const opening = waitForSocketOpen(pending.socket, new AbortController().signal, 10);
    const outcome = opening.then(
      () => ({ status: "opened" as const }),
      (error: unknown) => ({ status: "rejected" as const, error })
    );
    await vi.advanceTimersByTimeAsync(10);
    await expect(outcome).resolves.toMatchObject({
      status: "rejected",
      error: expect.objectContaining({ message: "TCP connection timed out" })
    });
    expect(pending.closeCalls()).toBe(1);
  });

  it("retries once after a timed-out open and keeps each attempt bounded", async () => {
    vi.useFakeTimers();
    const pending = mockSocket(new Promise<SocketInfo>(() => undefined));
    const opened = mockSocket();
    connectMock.mockReturnValueOnce(pending.socket).mockReturnValueOnce(opened.socket);
    const opening = connectTCP({ host: "gstatic.com", port: 443 }, new AbortController().signal);
    const outcome = opening.then(
      (connection) => ({ status: "opened" as const, writable: connection.writable }),
      (error: unknown) => ({ status: "rejected" as const, error })
    );

    await vi.advanceTimersByTimeAsync(10_000);

    await expect(outcome).resolves.toEqual({ status: "opened", writable: opened.socket.writable });
    expect(connectMock).toHaveBeenCalledTimes(2);
    expect(pending.closeCalls()).toBe(1);
    expect(opened.closeCalls()).toBe(0);
  });
});

/** Serves `data` in partial reads of at most 20 000 bytes, like a socket returning what is available. */
function byteSource(data: Uint8Array): ReadableStream<Uint8Array> {
  let offset = 0;
  return new ReadableStream({
    type: "bytes",
    pull(controller) {
      const request = controller.byobRequest;
      const requested = request?.view;
      if (request === null || requested === null || requested === undefined) return;
      if (offset >= data.byteLength) {
        controller.close();
        request.respond(0);
        return;
      }
      const view = new Uint8Array(requested.buffer, requested.byteOffset, requested.byteLength);
      const length = Math.min(view.byteLength, data.byteLength - offset, 20_000);
      view.set(data.subarray(offset, offset + length));
      offset += length;
      request.respond(length);
    }
  });
}

async function collect(stream: ReadableStream<Uint8Array>): Promise<{ bytes: number[]; largest: number }> {
  const reader = stream.getReader();
  const bytes: number[] = [];
  let largest = 0;
  for (;;) {
    const result = await reader.read();
    if (result.done) return { bytes, largest };
    largest = Math.max(largest, result.value.byteLength);
    for (const byte of result.value) bytes.push(byte);
  }
}

describe("large-chunk reading", () => {
  it("delivers every byte in order, in chunks larger than the 4 KiB default, and ends cleanly", async () => {
    const data = Uint8Array.from({ length: 50_000 }, (_, index) => index % 251);
    const { bytes, largest } = await collect(readInLargeChunks(byteSource(data), 65_536));
    expect(bytes).toEqual([...data]);
    expect(largest).toBeGreaterThan(4_096);
    expect(largest).toBeLessThanOrEqual(65_536);
  });

  it("ends an empty source without data", async () => {
    expect((await collect(readInLargeChunks(byteSource(new Uint8Array()), 65_536))).bytes).toEqual([]);
  });

  it("propagates cancellation to the source", async () => {
    let canceled = false;
    const source = new ReadableStream({
      type: "bytes",
      pull: () => undefined,
      cancel: () => {
        canceled = true;
      }
    });
    const reader = readInLargeChunks(source, 65_536).getReader();
    const pending = reader.read();
    await reader.cancel();
    await pending;
    expect(canceled).toBe(true);
  });
});
