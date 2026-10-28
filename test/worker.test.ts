import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { requestBytes } from "./fixtures";
import { trRequest } from "./trojan-fixtures";

describe("Worker HTTP and WebSocket boundary", () => {
  it("serves an innocuous HTTP response without proxy disclosure", async () => {
    const response = await SELF.fetch("https://edge.example.com/");
    expect(response.status).toBe(404);
    expect(await response.text()).toBe("Not Found\n");
  });

  it("rejects non-WebSocket requests to the endpoint", async () => {
    const response = await SELF.fetch("https://edge.example.com/unit-test-path-0001");
    expect(response.status).toBe(404);
  });

  it("rejects an invalid path without identifying the endpoint", async () => {
    const response = await SELF.fetch("https://edge.example.com/wrong", {
      headers: { Upgrade: "websocket" }
    });
    expect(response.status).toBe(404);
  });

  it.each([
    ["plaintext HTTP", "http://edge.example.com/unit-test-path-0001"],
    ["a port Cloudflare does not proxy for HTTPS", "https://edge.example.com:8080/unit-test-path-0001"]
  ])("rejects %s WebSocket upgrades with the generic response", async (_description, url) => {
    const response = await SELF.fetch(url, { headers: { Upgrade: "websocket" } });
    expect(response.status).toBe(404);
    expect(await response.text()).toBe("Not Found\n");
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it("upgrades the configured WebSocket path on the deployed hostname", async () => {
    const response = await SELF.fetch("https://worker.example/unit-test-path-0001", {
      headers: { Upgrade: "websocket" }
    });
    expect(response.status).toBe(101);
    expect(response.webSocket).not.toBeNull();
    response.webSocket?.accept();
    response.webSocket?.close(1000, "done");
  });

  it("keeps the Vl and Tr paths protocol-isolated", async () => {
    const cases = [
      {
        path: "/unit-test-path-0001",
        request: trRequest("unit-test-tr-password")
      },
      {
        path: "/unit-test-tr-path-0002",
        request: requestBytes()
      }
    ];

    for (const testCase of cases) {
      const response = await SELF.fetch(`https://worker.example${testCase.path}`, {
        headers: { Upgrade: "websocket" }
      });
      expect(response.status).toBe(101);
      const socket = response.webSocket!;
      socket.accept();
      const closed = new Promise<CloseEvent>((resolve) => socket.addEventListener("close", resolve, { once: true }));
      socket.send(testCase.request);
      const closeEvent = await closed;
      expect(closeEvent.code).toBe(1002);
      expect(closeEvent.reason).toBe("invalid request");
    }
  });

  it("rejects HTTP early data on the Tr-only path", async () => {
    const response = await SELF.fetch("https://worker.example/unit-test-tr-path-0002", {
      headers: {
        Upgrade: "websocket",
        "Sec-WebSocket-Protocol": "AA"
      }
    });
    expect(response.status).toBe(404);
  });

  it("accepts WebSocket early data in Sec-WebSocket-Protocol and negotiates it back", async () => {
    // Base64url([Vl version 0]); the session parser will await the rest of the header.
    const earlyData = "AA";
    const response = await SELF.fetch("https://worker.example/unit-test-path-0001", {
      headers: {
        Upgrade: "websocket",
        "Sec-WebSocket-Protocol": earlyData
      }
    });
    expect(response.status).toBe(101);
    expect(response.headers.get("Sec-WebSocket-Protocol")).toBe(earlyData);
    expect(response.webSocket).not.toBeNull();
    response.webSocket?.accept();
    response.webSocket?.close(1000, "done");
  });

  it("rejects malformed WebSocket early data", async () => {
    const response = await SELF.fetch("https://worker.example/unit-test-path-0001", {
      headers: {
        Upgrade: "websocket",
        "Sec-WebSocket-Protocol": "not base64url!"
      }
    });
    expect(response.status).toBe(404);
  });

  it.each(["443", "2053", "2083", "2087", "2096", "8443"])(
    "accepts HTTPS WebSocket connections on Cloudflare HTTPS port %s",
    async (port) => {
      const response = await SELF.fetch(`https://edge.example.com:${port}/unit-test-path-0001`, {
        headers: { Upgrade: "websocket" }
      });
      expect(response.status).toBe(101);
      response.webSocket?.accept();
      response.webSocket?.close(1000, "done");
    }
  );

  it.each(["2052", "2082", "2086", "2095", "8080"])(
    "rejects HTTP-only Cloudflare port %s for secure WebSocket",
    async (port) => {
      const response = await SELF.fetch(`https://edge.example.com:${port}/unit-test-path-0001`, {
        headers: { Upgrade: "websocket" }
      });
      expect(response.status).toBe(404);
    }
  );

  it("closes on text frames", async () => {
    const response = await SELF.fetch("https://edge.example.com/unit-test-path-0001", {
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
